import os
import sys
import json
import atexit
import argparse
import time
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
proj_root = Path(__file__).resolve().parents[1]
sys.path.append(str(proj_root))
from openai_client import OpenAIClient, is_empty

def _norm_key(record: Dict[str, Any], camel: str, snake: str):
    if camel in record:
        return camel
    if snake in record:
        return snake
    return camel

def _get(record: Dict[str, Any], camel: str, snake: str):
    k = _norm_key(record, camel, snake)
    return record.get(k)

def _set(record: Dict[str, Any], camel: str, snake: str, value: Any):
    k = _norm_key(record, camel, snake)
    record[k] = value

def _unique_key(rec: Dict[str, Any]):
    for k in ['cve', 'nvdCve', 'cnnvd', 'id']:
        v = rec.get(k)
        if not is_empty(v):
            return f'{k}:{str(v)}'
    return json.dumps(rec, ensure_ascii=False)

def _validate(rec: Dict[str, Any]):
    try:
        json.dumps(rec, ensure_ascii=False)
        return True
    except Exception:
        return False

def _hash_key(kind: str, text: str, target: str = 'English'):
    h = hashlib.sha256((kind + '|' + target + '|' + text).encode('utf-8')).hexdigest()
    return kind + ':' + h

def load_translate_cache(cache_file: Path):
    cache = {}
    if cache_file and cache_file.exists():
        try:
            with cache_file.open('r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                        k = item.get('key')
                        v = item.get('value')
                        if k and v is not None:
                            cache[k] = v
                    except Exception:
                        pass
        except Exception:
            pass
    return cache

def append_translate_cache(cache_file: Path, key: str, value: str):
    try:
        with cache_file.open('a', encoding='utf-8') as f:
            f.write(json.dumps({'key': key, 'value': value}, ensure_ascii=False) + '\n')
    except Exception:
        pass

def _fmt_time(sec: float):
    sec = int(max(sec, 0))
    h = sec // 3600
    m = (sec % 3600) // 60
    s = sec % 60
    if h > 0:
        return f"{h:02d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"

def _render_bar(current: int, total: int, start_time: float):
    elapsed = max(time.time() - start_time, 1e-6)
    rate = current / elapsed
    remain = max(total - current, 0)
    eta_sec = int(remain / rate) if rate > 0 else 0
    elapsed_fmt = _fmt_time(elapsed)
    eta_fmt = _fmt_time(eta_sec)
    pct = (current / total) if total else 0
    pct_text = f"{int(pct*100):3d}%"
    width = 100
    filled = int(pct * width)
    bar = '█' * filled + ' ' * (width - filled)
    return f"\r{pct_text}|{bar}| {current}/{total} [{elapsed_fmt}<{eta_fmt}, {rate:.2f}it/s]"

def process_files(input_files: List[Path], output_file: Path, client: OpenAIClient, progress_interval: int = 1000, debug: bool = False, cache_file: Path = None):
    seen = set()
    f = output_file.open('w', encoding='utf-8')
    f.write('[\n')
    atexit.register(lambda: f.write('\n]') if not f.closed else None)
    first = True
    total = 0
    completed = 0
    duplicates = 0
    invalid = 0
    vd_attempt = 0
    vd_translated = 0
    et_attempt = 0
    et_translated = 0
    cached_hits = 0
    if not client.api_key:
        print('未检测到 OPENAI_API_KEY，跳过翻译补全')
    all_data = []
    grand_total = 0
    start_time = time.time()
    cache = load_translate_cache(cache_file) if cache_file else {}
    if cache_file:
        print(f'已加载翻译缓存: {len(cache)}')
    for p in input_files:
        try:
            data = json.loads(p.read_text(encoding='utf-8'))
            if isinstance(data, list):
                all_data.append((p, data))
                grand_total += len(data)
                print(f'读取文件: {p}，记录数: {len(data)}')
        except Exception:
            print(f'读取失败: {p}')
            pass
    print(f'总记录数: {grand_total}')
    for p, data in all_data:
        print(f'开始处理: {p}')
        for rec in data:
            if not isinstance(rec, dict):
                continue
            key = _unique_key(rec)
            if key in seen:
                duplicates += 1
                total += 1
                print(_render_bar(total, grand_total, start_time), end='', flush=True)
                continue
            seen.add(key)
            vd = _get(rec, 'vulnDescription', 'vuln_description')
            desc = rec.get('description')
            if is_empty(vd) and not is_empty(desc):
                vd_attempt += 1
                k1 = _hash_key('vulnDescription', str(desc))
                if k1 in cache:
                    t = cache[k1]
                    cached_hits += 1
                else:
                    t = client.translate(str(desc), 'English')
                if debug:
                    print(f'[vulnDescription] 原文: {str(desc)}')
                    print(f'[vulnDescription] 结果: {str(t) if t else ""}')
                if t and not is_empty(t):
                    _set(rec, 'vulnDescription', 'vuln_description', t)
                    if cache_file and k1 not in cache:
                        cache[k1] = t
                        append_translate_cache(cache_file, k1, t)
                    vd_translated += 1
            et = _get(rec, 'enTitle', 'en_title')
            title = rec.get('title')
            if is_empty(et) and not is_empty(title):
                et_attempt += 1
                k2 = _hash_key('enTitle', str(title))
                if k2 in cache:
                    t2 = cache[k2]
                    cached_hits += 1
                else:
                    t2 = client.translate(str(title), 'English')
                if debug:
                    print(f'[enTitle] 原文: {str(title)}')
                    print(f'[enTitle] 结果: {str(t2) if t2 else ""}')
                if t2 and not is_empty(t2):
                    _set(rec, 'enTitle', 'en_title', t2)
                    if cache_file and k2 not in cache:
                        cache[k2] = t2
                        append_translate_cache(cache_file, k2, t2)
                    et_translated += 1
            if not _validate(rec):
                invalid += 1
                total += 1
                print(_render_bar(total, grand_total, start_time), end='', flush=True)
                continue
            if first:
                first = False
            else:
                f.write(',\n')
            f.write(json.dumps(rec, ensure_ascii=False))
            f.flush()
            completed += 1
            total += 1
            print(_render_bar(total, grand_total, start_time), end='', flush=True)
    print()
    f.write('\n]')
    f.flush()
    f.close()
    print(f'输入记录: {total}')
    print(f'写入记录: {completed}')
    print(f'重复记录: {duplicates}')
    print(f'非法记录: {invalid}')
    print(f'vulnDescription 待翻译: {vd_attempt}, 已翻译: {vd_translated}')
    print(f'enTitle 待翻译: {et_attempt}, 已翻译: {et_translated}')
    print(f'缓存命中: {cached_hits}')

def main():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument('-o', '--output', required=False)
    parser.add_argument('--debug', default=False, action='store_true')
    parser.add_argument('--progress-interval', type=int, default=1000)
    parser.add_argument('--cache-file', type=str, default=str((Path(__file__).resolve().parent / 'translate_cache.jsonl')))
    parser.add_argument('inputs', nargs='*')
    args = parser.parse_args()
    inputs = [Path(x) for x in args.inputs if x]
    if not inputs:
        print('未提供输入文件')
        sys.exit(1)
    for p in inputs:
        if not p.exists():
            print(f'输入文件不存在: {p}')
            sys.exit(1)
    if args.output:
        out = Path(args.output)
    else:
        out = Path(__file__).resolve().parent / f'CVE_full_{datetime.now().strftime("%Y%m%d")}.json'
    client = OpenAIClient()
    cache_path = Path(args.cache_file) if args.cache_file else None
    process_files(inputs, out, client, progress_interval=args.progress_interval, debug=args.debug, cache_file=cache_path)

if __name__ == '__main__':
    main()
