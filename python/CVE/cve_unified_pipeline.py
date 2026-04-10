import argparse
import json
import logging
import os
import pathlib
import re
import sys
import tempfile
import urllib.request
import zipfile
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    from tqdm import tqdm
except Exception:
    def tqdm(x, **kwargs):
        return x

BASE_DIR = pathlib.Path(__file__).resolve().parent
sys.path.append(str(BASE_DIR.parent))

from cve_processor import CVEProcessor
from openai_client import OpenAIClient, is_empty
from translation_client import TranslationClient


def detect_language(text: Any) -> str:
    s = str(text or "").strip()
    if not s:
        return "unknown"
    zh_count = len(re.findall(r"[\u4e00-\u9fff]", s))
    en_count = len(re.findall(r"[A-Za-z]", s))
    if zh_count > 0 and en_count == 0:
        return "zh"
    if en_count > 0 and zh_count == 0:
        return "en"
    if zh_count == 0 and en_count == 0:
        return "unknown"
    return "mixed"


def has_chinese(text: Any) -> bool:
    s = str(text or "")
    return bool(re.search(r"[\u4e00-\u9fff]", s))


def normalize_text(text: Any) -> str:
    return str(text or "").strip()


def unique_key(rec: Dict[str, Any]) -> str:
    for k in ["cve", "nvdCve", "cnnvd", "id"]:
        v = normalize_text(rec.get(k))
        if v:
            return f"{k}:{v}"
    return json.dumps(rec, ensure_ascii=False, sort_keys=True)


def load_json(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_json_list(path: pathlib.Path) -> List[Dict[str, Any]]:
    data = load_json(path)
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    return []


def load_kv_cache(path: pathlib.Path) -> Dict[str, str]:
    cache: Dict[str, str] = {}
    if not path.exists():
        return cache
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            item = json.loads(s)
            k = normalize_text(item.get("key") or item.get("source") or item.get("cve"))
            v = normalize_text(item.get("value") or item.get("solution"))
            if k and v:
                cache[k] = v
        except Exception:
            continue
    return cache


def normalize_direction(target_lang: str) -> str:
    t = normalize_text(target_lang).lower()
    if t in {"english", "en"}:
        return "to_en"
    if t in {"中文", "chinese", "zh", "zh-cn", "cn"}:
        return "to_zh"
    return "any"


def parse_legacy_translate_key(raw_key: str, raw_kind: str) -> Tuple[str, str, str]:
    key = normalize_text(raw_key)
    kind = normalize_text(raw_kind)
    direction = "any"
    m = re.match(r"^([^:]+):(中文|English):(.*)$", key)
    if m:
        parsed_kind = normalize_text(m.group(1))
        lang = normalize_text(m.group(2))
        parsed_key = normalize_text(m.group(3))
        if parsed_kind:
            kind = parsed_kind
        if lang == "中文":
            direction = "to_zh"
        elif lang.lower() == "english":
            direction = "to_en"
        key = parsed_key
    return key, kind, direction


def load_translate_cache(path: pathlib.Path) -> Dict[Tuple[str, str, str], str]:
    cache: Dict[Tuple[str, str, str], str] = {}
    if not path.exists():
        return cache
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            item = json.loads(s)
            raw_key = item.get("key") or item.get("source")
            raw_value = item.get("value")
            raw_kind = item.get("kind")
            raw_direction = item.get("direction") or item.get("target") or item.get("target_lang")
            key, kind, parsed_direction = parse_legacy_translate_key(raw_key, raw_kind)
            value = normalize_text(raw_value)
            if not key or not value:
                continue
            direction = normalize_direction(raw_direction) if normalize_text(raw_direction) else parsed_direction
            cache[(kind, direction, key)] = value
            cache[(kind, "any", key)] = value
            if not kind:
                cache[("", direction, key)] = value
                cache[("", "any", key)] = value
        except Exception:
            continue
    return cache


def append_kv_cache(path: pathlib.Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")


def normalize_rule_line(text: str) -> str:
    return normalize_text(text).lower().replace("_", "-")


def load_rules(path: pathlib.Path) -> List[Tuple[str, str]]:
    if not path.exists():
        logging.warning("规则文件不存在: %s", path)
        return []
    lines: List[Tuple[str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        raw = normalize_text(line)
        if not raw:
            continue
        lines.append((raw, normalize_rule_line(raw)))
    logging.info("已加载规则行数: %d", len(lines))
    return lines


def sanitize_solution(text: Any) -> str:
    s = str(text or "").replace("**", "")
    parts = [x.strip() for x in s.splitlines() if x.strip()]
    return "\n".join(parts).strip()


def translate_with_cache(
    client: TranslationClient,
    cache: Dict[Tuple[str, str, str], str],
    cache_path: pathlib.Path,
    text: str,
    target_lang: str,
    kind: str,
    trace: Optional[Dict[str, Any]] = None,
    validator: Optional[OpenAIClient] = None,
    validate_translation_result: bool = False
) -> Optional[str]:
    s = normalize_text(text)
    if not s:
        return None
    direction = normalize_direction(target_lang)
    kind_norm = normalize_text(kind)
    for cache_key in [
        (kind_norm, direction, s),
        (kind_norm, "any", s),
        ("", direction, s),
        ("", "any", s)
    ]:
        if cache_key in cache:
            if trace is not None:
                trace["translate_cache_hit"] = True
                trace["translate_cache_hit_count"] = int(trace.get("translate_cache_hit_count", 0)) + 1
            return cache[cache_key]
    if trace is not None:
        trace["translate_cache_miss_count"] = int(trace.get("translate_cache_miss_count", 0)) + 1
    out = client.translate(s, target_lang=target_lang)
    out_clean = normalize_text(out)
    if out_clean and validate_translation_result and validator and validator.api_key:
        if trace is not None:
            trace["translation_validation_enabled"] = True
        ok = bool(validator.is_translation_valid(s, out_clean, target_lang=target_lang))
        if trace is not None:
            trace["translation_validation_checked_count"] = int(trace.get("translation_validation_checked_count", 0)) + 1
            if ok:
                trace["translation_validation_pass_count"] = int(trace.get("translation_validation_pass_count", 0)) + 1
            else:
                trace["translation_validation_fail_count"] = int(trace.get("translation_validation_fail_count", 0)) + 1
        if not ok:
            return None
    if out_clean:
        cache[(kind_norm, direction, s)] = out_clean
        cache[(kind_norm, "any", s)] = out_clean
        append_kv_cache(cache_path, {"key": s, "value": out_clean, "kind": kind_norm, "direction": direction})
        return out_clean
    return None


def fix_bilingual_pair(
    rec: Dict[str, Any],
    zh_key: str,
    en_key: str,
    translator: TranslationClient,
    translate_cache: Dict[Tuple[str, str, str], str],
    translate_cache_path: pathlib.Path,
    trace: Optional[Dict[str, Any]] = None,
    validator: Optional[OpenAIClient] = None,
    validate_translation_result: bool = False
) -> None:
    zh_val = normalize_text(rec.get(zh_key))
    en_val = normalize_text(rec.get(en_key))
    if zh_val:
        if not has_chinese(zh_val):
            source_for_zh = zh_val
            tr_zh = translate_with_cache(
                translator,
                translate_cache,
                translate_cache_path,
                source_for_zh,
                "中文",
                kind=zh_key,
                trace=trace,
                validator=validator,
                validate_translation_result=validate_translation_result
            )
            if tr_zh:
                zh_val = tr_zh
    else:
        if en_val:
            tr_zh = translate_with_cache(
                translator,
                translate_cache,
                translate_cache_path,
                en_val,
                "中文",
                kind=zh_key,
                trace=trace,
                validator=validator,
                validate_translation_result=validate_translation_result
            )
            if tr_zh:
                zh_val = tr_zh
    if en_val:
        if has_chinese(en_val):
            source_for_en = en_val
            tr_en = translate_with_cache(
                translator,
                translate_cache,
                translate_cache_path,
                source_for_en,
                "English",
                kind=en_key,
                trace=trace,
                validator=validator,
                validate_translation_result=validate_translation_result
            )
            if tr_en:
                en_val = tr_en
    else:
        if zh_val:
            tr_en = translate_with_cache(
                translator,
                translate_cache,
                translate_cache_path,
                zh_val,
                "English",
                kind=en_key,
                trace=trace,
                validator=validator,
                validate_translation_result=validate_translation_result
            )
            if tr_en:
                en_val = tr_en
    if zh_val:
        rec[zh_key] = zh_val
    if en_val:
        rec[en_key] = en_val


def fill_solution(
    rec: Dict[str, Any],
    rules: List[Tuple[str, str]],
    ai: OpenAIClient,
    solution_cache: Dict[str, str],
    solution_cache_path: pathlib.Path,
    trace: Optional[Dict[str, Any]] = None
) -> None:
    cve_id = normalize_text(rec.get("cve") or rec.get("nvdCve"))
    cur = sanitize_solution(rec.get("solution"))
    if cur:
        rec["solution"] = cur
        if trace is not None:
            trace["solution_cache_hit"] = False
            trace["solution_source"] = "record"
        if cve_id and cve_id not in solution_cache:
            solution_cache[cve_id] = cur
            append_kv_cache(solution_cache_path, {"cve": cve_id, "solution": cur, "according": "existing"})
        return
    if not cve_id:
        if trace is not None:
            trace["solution_cache_hit"] = False
            trace["solution_source"] = "no_cve"
        return
    if cve_id in solution_cache and solution_cache[cve_id]:
        rec["solution"] = solution_cache[cve_id]
        if trace is not None:
            trace["solution_cache_hit"] = True
            trace["solution_source"] = "cache"
        return
    cve_norm = normalize_rule_line(cve_id)
    matched = [line for line, norm in rules if cve_norm and cve_norm in norm]
    advice_text = "\n".join(matched) if matched else None
    source = "suggest" if matched else "AI"
    generated = ai.generate_solution_with_advice(cve_id=cve_id, vuln=rec, advice_text=advice_text, target_lang="中文")
    clean = sanitize_solution(generated)
    if clean:
        rec["solution"] = clean
        solution_cache[cve_id] = clean
        append_kv_cache(solution_cache_path, {"cve": cve_id, "solution": clean, "according": source})
        if trace is not None:
            trace["solution_cache_hit"] = False
            trace["solution_source"] = source
    else:
        if trace is not None:
            trace["solution_cache_hit"] = False
            trace["solution_source"] = "empty"


def merge_records(records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    for rec in records:
        key = unique_key(rec)
        if key not in merged:
            merged[key] = dict(rec)
            continue
        cur = merged[key]
        for k, v in rec.items():
            if is_empty(cur.get(k)) and not is_empty(v):
                cur[k] = v
            elif k == "id" and not is_empty(v):
                cur[k] = v
    return list(merged.values())


def download_file(url: str, target_dir: pathlib.Path) -> List[pathlib.Path]:
    target_dir.mkdir(parents=True, exist_ok=True)
    filename = os.path.basename(url.split("?")[0]) or f"download_{int(datetime.now().timestamp())}.dat"
    dst = target_dir / filename
    logging.info("下载: %s", url)
    with urllib.request.urlopen(url, timeout=120) as resp:
        content = resp.read()
    dst.write_bytes(content)
    outputs: List[pathlib.Path] = []
    if dst.suffix.lower() == ".zip":
        with zipfile.ZipFile(dst, "r") as zf:
            for member in zf.namelist():
                if member.lower().endswith(".xml"):
                    zf.extract(member, path=target_dir)
                    outputs.append(target_dir / member)
        logging.info("已解压XML数量: %d", len(outputs))
        return outputs
    if dst.suffix.lower() == ".xml":
        outputs.append(dst)
    return outputs


def collect_download_urls(download_urls: List[str], manifest: Optional[pathlib.Path]) -> List[str]:
    urls = [u.strip() for u in download_urls if normalize_text(u)]
    if manifest and manifest.exists():
        for line in manifest.read_text(encoding="utf-8").splitlines():
            s = normalize_text(line)
            if s and not s.startswith("#"):
                urls.append(s)
    seen = set()
    result: List[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            result.append(u)
    return result


def build_output_path(output_arg: Optional[str], date_str: str) -> pathlib.Path:
    if output_arg:
        p = pathlib.Path(output_arg)
        if p.suffix.lower() == ".json":
            return p
        return p / f"CVE_full_{date_str}.json"
    return BASE_DIR / f"CVE_full_{date_str}.json"


def build_jsonl_output_path(json_output_path: pathlib.Path) -> pathlib.Path:
    return json_output_path.with_suffix(".jsonl")


def validate_records_for_json(records: List[Dict[str, Any]]) -> None:
    for i, rec in enumerate(records, start=1):
        try:
            line = json.dumps(rec, ensure_ascii=False)
            parsed = json.loads(line)
            if not isinstance(parsed, dict):
                raise ValueError(f"第{i}条记录结构错误，必须为对象")
        except Exception as e:
            raise ValueError(f"第{i}条记录JSON校验失败: {e}")


def atomic_write_json(path: pathlib.Path, records: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=str(path.parent), suffix=".tmp") as tmp:
        json.dump(records, tmp, ensure_ascii=False, indent=2)
        temp_path = pathlib.Path(tmp.name)
    os.replace(str(temp_path), str(path))


def atomic_write_jsonl(path: pathlib.Path, records: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=str(path.parent), suffix=".tmp") as tmp:
        for i, rec in enumerate(records, start=1):
            try:
                line = json.dumps(rec, ensure_ascii=False)
                parsed = json.loads(line)
                if not isinstance(parsed, dict):
                    raise ValueError(f"第{i}行结构错误，必须为对象")
            except Exception as e:
                raise ValueError(f"第{i}行JSONL校验失败: {e}")
            tmp.write(line)
            tmp.write("\n")
        temp_path = pathlib.Path(tmp.name)
    os.replace(str(temp_path), str(path))


def setup_debug_logger(enabled: bool, log_path: pathlib.Path) -> Optional[logging.Logger]:
    if not enabled:
        return None
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("cve_debug")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    logger.handlers.clear()
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    logger.addHandler(handler)
    return logger


def close_debug_logger(logger: Optional[logging.Logger]) -> None:
    if not logger:
        return
    handlers = list(logger.handlers)
    for handler in handlers:
        handler.flush()
        handler.close()
        logger.removeHandler(handler)


def record_key(rec: Dict[str, Any]) -> str:
    return normalize_text(rec.get("cve")) or normalize_text(rec.get("nvdCve")) or normalize_text(rec.get("cnnvd")) or "UNKNOWN"


def strip_null_fields(data: Any) -> Any:
    if isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            if v is None:
                continue
            cleaned_v = strip_null_fields(v)
            cleaned[k] = cleaned_v
        return cleaned
    if isinstance(data, list):
        return [strip_null_fields(x) for x in data if x is not None]
    return data


def exceeds_name_field_length_limit(rec: Dict[str, Any], max_len: int) -> bool:
    for key in ["title", "threatName", "enTitle", "threatNameEng"]:
        v = normalize_text(rec.get(key))
        if v and len(v) > max_len:
            return True
    return False


def assign_output_ids(records: List[Dict[str, Any]]) -> None:
    used = set()
    for idx, rec in enumerate(records, start=1):
        candidates = [
            normalize_text(rec.get("cve")),
            normalize_text(rec.get("nvdCve")),
            normalize_text(rec.get("cnnvd")),
            normalize_text(rec.get("id"))
        ]
        base_id = ""
        for c in candidates:
            if c:
                base_id = c
                break
        if not base_id:
            base_id = str(idx)
        out_id = base_id
        seq = 2
        while out_id in used:
            out_id = f"{base_id}_{seq}"
            seq += 1
        rec["id"] = out_id
        used.add(out_id)


def process_pipeline(args: argparse.Namespace) -> pathlib.Path:
    date_str = datetime.now().strftime(args.date_format)
    output_path = build_output_path(args.output, date_str)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    debug_log_path = pathlib.Path(args.debug_log).resolve() if normalize_text(args.debug_log) else output_path.parent / "debug.log"
    debug_logger = setup_debug_logger(bool(args.debug), debug_log_path)
    if debug_logger:
        debug_logger.debug("debug logging enabled")
    data_dir = pathlib.Path(args.data_dir).resolve()
    urls = collect_download_urls(args.download_url or [], pathlib.Path(args.download_manifest).resolve() if args.download_manifest else None)
    if urls:
        for u in tqdm(urls, desc="下载CVE文件", unit="个"):
            try:
                download_file(u, data_dir)
            except Exception as e:
                logging.exception("下载失败: %s", e)
    processor = CVEProcessor(data_dir=str(data_dir), existing_data_file=None)
    xml_records = processor.process_all_files()
    logging.info("XML解析记录数: %d", len(xml_records))
    input_records: List[Dict[str, Any]] = []
    for p in args.input_json:
        jpath = pathlib.Path(p).resolve()
        if not jpath.exists():
            logging.warning("输入JSON不存在: %s", jpath)
            continue
        loaded = load_json_list(jpath)
        input_records.extend(loaded)
        logging.info("读取JSON记录: %s -> %d", jpath, len(loaded))
    records = merge_records([*input_records, *xml_records])
    logging.info("合并去重后记录数: %d", len(records))
    translator = TranslationClient(debug=False)
    ai = OpenAIClient()
    validate_translation_result = bool(getattr(args, "validate_translation_result", False))
    max_name_field_length = int(getattr(args, "max_name_field_length", 250))
    if not translator.can_translate():
        logging.warning("未检测到翻译配置，语言纠正与英文建议补全可能不完整")
    if not ai.api_key:
        logging.warning("未检测到 OPENAI_API_KEY，缺失修复建议将无法自动生成")
    if validate_translation_result and not ai.api_key:
        logging.warning("已启用翻译结果校验，但未检测到 OPENAI_API_KEY，将跳过校验")
    translate_cache_path = pathlib.Path(args.translate_cache).resolve()
    solution_cache_path = pathlib.Path(args.solution_cache).resolve()
    translate_cache = load_translate_cache(translate_cache_path)
    solution_cache = load_kv_cache(solution_cache_path)
    rules = load_rules(pathlib.Path(args.rules_file).resolve())
    bar = tqdm(records, desc="补全与翻译", unit="条")
    for rec in bar:
        if not isinstance(rec, dict):
            continue
        rec_id = record_key(rec)
        trace: Dict[str, Any] = {
            "translate_cache_hit": False,
            "translate_cache_hit_count": 0,
            "translate_cache_miss_count": 0,
            "solution_cache_hit": False,
            "solution_source": "",
            "translation_validation_enabled": validate_translation_result,
            "translation_validation_checked_count": 0,
            "translation_validation_pass_count": 0,
            "translation_validation_fail_count": 0
        }
        if debug_logger:
            debug_logger.debug("before %s %s", rec_id, json.dumps(strip_null_fields(rec), ensure_ascii=False, sort_keys=True))
        fix_bilingual_pair(
            rec,
            "title",
            "enTitle",
            translator,
            translate_cache,
            translate_cache_path,
            trace=trace,
            validator=ai,
            validate_translation_result=validate_translation_result
        )
        if is_empty(rec.get("threatName")) and not is_empty(rec.get("title")):
            rec["threatName"] = rec.get("title")
        if is_empty(rec.get("threatNameEng")) and not is_empty(rec.get("enTitle")):
            rec["threatNameEng"] = rec.get("enTitle")
        fix_bilingual_pair(
            rec,
            "threatName",
            "threatNameEng",
            translator,
            translate_cache,
            translate_cache_path,
            trace=trace,
            validator=ai,
            validate_translation_result=validate_translation_result
        )
        fix_bilingual_pair(
            rec,
            "description",
            "vulnDescription",
            translator,
            translate_cache,
            translate_cache_path,
            trace=trace,
            validator=ai,
            validate_translation_result=validate_translation_result
        )
        desc_eng = normalize_text(rec.get("descriptionEng"))
        if desc_eng:
            if has_chinese(desc_eng):
                translated_desc_eng = translate_with_cache(
                    translator,
                    translate_cache,
                    translate_cache_path,
                    desc_eng,
                    "English",
                    kind="descriptionEng",
                    trace=trace,
                    validator=ai,
                    validate_translation_result=validate_translation_result
                )
                if translated_desc_eng:
                    desc_eng = translated_desc_eng
        else:
            source_eng = normalize_text(rec.get("vulnDescription"))
            if source_eng and not has_chinese(source_eng):
                desc_eng = source_eng
            else:
                source_cn = normalize_text(rec.get("description"))
                if source_cn:
                    translated_desc_eng = translate_with_cache(
                        translator,
                        translate_cache,
                        translate_cache_path,
                        source_cn,
                        "English",
                        kind="descriptionEng",
                        trace=trace,
                        validator=ai,
                        validate_translation_result=validate_translation_result
                    )
                    if translated_desc_eng:
                        desc_eng = translated_desc_eng
        if desc_eng:
            rec["descriptionEng"] = desc_eng
        fill_solution(rec, rules, ai, solution_cache, solution_cache_path, trace=trace)
        fix_bilingual_pair(
            rec,
            "solution",
            "enSolution",
            translator,
            translate_cache,
            translate_cache_path,
            trace=trace,
            validator=ai,
            validate_translation_result=validate_translation_result
        )
        if debug_logger:
            debug_logger.debug("cache %s %s", rec_id, json.dumps(trace, ensure_ascii=False, sort_keys=True))
            debug_logger.debug("after %s %s", rec_id, json.dumps(strip_null_fields(rec), ensure_ascii=False, sort_keys=True))
    filtered_records: List[Dict[str, Any]] = []
    skipped_by_name_len = 0
    for rec in records:
        if exceeds_name_field_length_limit(rec, max_name_field_length):
            skipped_by_name_len += 1
            if debug_logger:
                debug_logger.debug("skip_by_name_len %s %s", record_key(rec), json.dumps(strip_null_fields(rec), ensure_ascii=False, sort_keys=True))
            continue
        filtered_records.append(rec)
    assign_output_ids(filtered_records)
    validate_records_for_json(filtered_records)
    jsonl_path = build_jsonl_output_path(output_path)
    atomic_write_json(output_path, filtered_records)
    atomic_write_jsonl(jsonl_path, filtered_records)
    close_debug_logger(debug_logger)
    logging.info("输出文件: %s", output_path)
    logging.info("输出文件: %s", jsonl_path)
    logging.info("长度过滤跳过记录数: %d (阈值: %d)", skipped_by_name_len, max_name_field_length)
    logging.info("输出记录数: %d", len(filtered_records))
    return output_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--data-dir", default=str(BASE_DIR / "data"))
    parser.add_argument("--download-url", action="append", default=[])
    parser.add_argument("--download-manifest", default=None)
    parser.add_argument("--input-json", nargs="*", default=[])
    parser.add_argument("--rules-file", default=str(BASE_DIR / "rules.sugst"))
    parser.add_argument("--translate-cache", default=str(BASE_DIR / "translate_cache.jsonl"))
    parser.add_argument("--solution-cache", default=str(BASE_DIR / "solutions_cache.jsonl"))
    parser.add_argument("--output", default=None)
    parser.add_argument("--date-format", default="%Y%m%d")
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--debug", action="store_true", default=False)
    parser.add_argument("--debug-log", default="debug.log")
    parser.add_argument("--validate-translation-result", action="store_true", default=False)
    parser.add_argument("--max-name-field-length", type=int, default=250)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    logging.basicConfig(level=getattr(logging, str(args.log_level).upper(), logging.INFO), format="[%(levelname)s] %(message)s")
    process_pipeline(args)


if __name__ == "__main__":
    main()
