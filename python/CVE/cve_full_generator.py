import os
import sys
import json
import atexit
import argparse
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

def process_files(input_files: List[Path], output_file: Path, client: OpenAIClient):
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
    if not client.api_key:
        print('未检测到 OPENAI_API_KEY，跳过翻译补全')
    for p in input_files:
        try:
            data = json.loads(p.read_text(encoding='utf-8'))
            if not isinstance(data, list):
                continue
            for rec in data:
                if not isinstance(rec, dict):
                    continue
                key = _unique_key(rec)
                if key in seen:
                    duplicates += 1
                    continue
                seen.add(key)
                total += 1
                vd = _get(rec, 'vulnDescription', 'vuln_description')
                desc = rec.get('description')
                if is_empty(vd) and not is_empty(desc):
                    vd_attempt += 1
                    t = client.translate(str(desc), 'English')
                    if t and not is_empty(t):
                        _set(rec, 'vulnDescription', 'vuln_description', t)
                        vd_translated += 1
                et = _get(rec, 'enTitle', 'en_title')
                title = rec.get('title')
                if is_empty(et) and not is_empty(title):
                    et_attempt += 1
                    t2 = client.translate(str(title), 'English')
                    if t2 and not is_empty(t2):
                        _set(rec, 'enTitle', 'en_title', t2)
                        et_translated += 1
                if not _validate(rec):
                    invalid += 1
                    continue
                if first:
                    first = False
                else:
                    f.write(',\n')
                f.write(json.dumps(rec, ensure_ascii=False))
                f.flush()
                completed += 1
        except Exception:
            continue
    f.write('\n]')
    f.flush()
    f.close()
    print(f'输入记录: {total}')
    print(f'写入记录: {completed}')
    print(f'重复记录: {duplicates}')
    print(f'非法记录: {invalid}')
    print(f'vulnDescription 待翻译: {vd_attempt}, 已翻译: {vd_translated}')
    print(f'enTitle 待翻译: {et_attempt}, 已翻译: {et_translated}')

def main():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument('-o', '--output', required=False)
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
    process_files(inputs, out, client)

if __name__ == '__main__':
    main()
