import json
import re
import pathlib
import sys
import logging
try:
    from tqdm import tqdm
except Exception:
    def tqdm(x, **kwargs):
        return x
sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from openai_client import OpenAIClient, is_empty

def normalize(text):
    return str(text or '').lower().replace('_', '-').strip()

def sanitize_solution(text):
    s = str(text or '')
    s = s.replace('**', '')
    lines = [ln.strip() for ln in s.splitlines()]
    lines = [ln for ln in lines if ln]
    return '\n'.join(lines).strip()

def load_rule_lines(path):
    lines = []
    p = pathlib.Path(path)
    if not p.exists():
        logging.warning(f'规则文件不存在: {p}')
        return lines
    for i, line in enumerate(p.read_text(encoding='utf-8').splitlines(), start=1):
        s = line.strip()
        if not s:
            continue
        lines.append((s, normalize(s), i))
    logging.info(f'已加载处置建议行数: {len(lines)}')
    return lines

def main():
    logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
    base = pathlib.Path(__file__).resolve().parent
    rules_path = pathlib.Path(r'F:\OtherProjects\SuricataRules\rules.sugst')
    input_path = base / 'CVE_full_20251205.json'
    output_path = base / 'CVE_full_20251205_solution.json'
    cache_path = base / 'solutions_cache.jsonl'
    logging.info(f'读取漏洞库: {input_path}')
    try:
        data = json.loads(input_path.read_text(encoding='utf-8'))
    except Exception as e:
        logging.error(f'读取漏洞库失败: {e}')
        return
    rules_lines = load_rule_lines(rules_path)
    client = OpenAIClient()
    if not client.api_key:
        logging.warning('未检测到 OPENAI_API_KEY，将跳过生成修复建议')
    cache = {}
    if cache_path.exists():
        for line in cache_path.read_text(encoding='utf-8').splitlines():
            s = line.strip()
            if not s:
                continue
            try:
                obj = json.loads(s)
                kc = str(obj.get('cve') or '').strip()
                kv = sanitize_solution(str(obj.get('solution') or '').strip())
                if kc and kv:
                    cache[kc] = kv
            except Exception:
                pass
    fh = cache_path.open('a', encoding='utf-8')
    filled = 0
    skipped_no_rule = 0
    skipped_has_solution = 0
    total = len(data)
    bar = tqdm(data, desc='处理漏洞', unit='条')
    for vuln in bar:
        raw_cve = vuln.get('cve') if isinstance(vuln, dict) else None
        if is_empty(raw_cve):
            raw_cve = vuln.get('nvdCve') if isinstance(vuln, dict) else None
        cve = str(raw_cve or '').strip()
        if is_empty(vuln.get('solution')):
            if is_empty(cve):
                skipped_no_rule += 1
                bar.set_postfix(filled=filled, skipped_no_rule=skipped_no_rule, skipped_has_solution=skipped_has_solution)
                continue
            if cve in cache and not is_empty(cache[cve]):
                vuln['solution'] = cache[cve]
                filled += 1
                logging.info(f'使用缓存修复建议: {cve}')
                bar.set_postfix(filled=filled, skipped_no_rule=skipped_no_rule, skipped_has_solution=skipped_has_solution)
                continue
            cve_norm = normalize(cve)
            if not cve_norm:
                skipped_no_rule += 1
                bar.set_postfix(filled=filled, skipped_no_rule=skipped_no_rule, skipped_has_solution=skipped_has_solution)
                continue
            matched = [rl for rl, norm, ln in rules_lines if cve_norm in norm]
            advice_text = None
            according = 'AI'
            if matched:
                advice_text = '\n'.join(matched)
                according = 'suggest'
                logging.info(f'匹配到 {cve} 的处置建议行数: {len(matched)}')
            
            sol = None
            if client.api_key:
                sol = client.generate_solution_with_advice(cve_id=cve, vuln=vuln, advice_text=advice_text, target_lang='中文')
            if sol and not is_empty(sol):
                clean = sanitize_solution(sol)
                vuln['solution'] = clean
                try:
                    fh.write(json.dumps({'cve': cve, 'solution': clean, 'according': according}, ensure_ascii=False) + '\n')
                    fh.flush()
                    cache[cve] = clean
                except Exception:
                    pass
                logging.info(f'调用模型输出预览: {cve} | 来源 {according} | 长度 {len(clean)} | 文本\n{clean}')
                filled += 1
            else:
                logging.warning(f'未生成修复建议或返回为空: {cve}')
            bar.set_postfix(filled=filled, skipped_no_rule=skipped_no_rule, skipped_has_solution=skipped_has_solution)
        else:
            skipped_has_solution += 1
            bar.set_postfix(filled=filled, skipped_no_rule=skipped_no_rule, skipped_has_solution=skipped_has_solution)
    logging.info(f'处理完成，总计 {total} 条，填充 {filled} 条，跳过(无规则匹配或无CVE) {skipped_no_rule} 条，已有方案 {skipped_has_solution} 条')
    output_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    logging.info(f'输出文件: {output_path}')
    try:
        fh.close()
    except Exception:
        pass

if __name__ == '__main__':
    main()
