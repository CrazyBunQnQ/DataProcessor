import json
import re
import pathlib
import sys
sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from openai_client import OpenAIClient, is_empty

def load_advice_map(path):
    m = {}
    p = pathlib.Path(path)
    if not p.exists():
        return m
    for line in p.read_text(encoding='utf-8').splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except Exception:
            continue
        advice_text = str(obj.get('advice') or '').strip()
        text = ' '.join(str(obj.get(k) or '') for k in ('attack', 'advice', 'harm', 'theory'))
        cves = set(re.findall(r'CVE-\d{4}-\d+', text))
        rnames = obj.get('ruleNameList')
        if isinstance(rnames, list):
            for v in rnames:
                cves.update(re.findall(r'CVE-\d{4}-\d+', str(v)))
        v = obj.get('cve')
        if isinstance(v, str) and re.match(r'^CVE-\d{4}-\d+$', v.strip()):
            cves.add(v.strip())
        for cv in cves:
            if advice_text:
                m.setdefault(cv, []).append(advice_text)
    return m

def choose_advice(advice_list):
    return '\n'.join(sorted(set(advice_list)))

def main():
    base = pathlib.Path(__file__).resolve().parent
    rules_path = pathlib.Path(r'F:\OtherProjects\SuricataRules\rules.sugst')
    input_path = base / 'CVE_full_20251205.json'
    output_path = base / 'CVE_full_20251205_solution.json'
    advice_map = load_advice_map(rules_path)
    data = json.loads(input_path.read_text(encoding='utf-8'))
    client = OpenAIClient()
    for vuln in data:
        cve = str(vuln.get('cve') or vuln.get('nvdCve') or '').strip()
        if is_empty(vuln.get('solution')):
            adv = advice_map.get(cve)
            if not adv:
                continue
            advice_text = choose_advice(adv)
            sol = client.generate_solution_with_advice(cve_id=cve, vuln=vuln, advice_text=advice_text, target_lang='中文')
            if sol and not is_empty(sol):
                vuln['solution'] = sol
    output_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
