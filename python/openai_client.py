import os
import json
import time
import pathlib
import requests

def _load_env():
    paths = [pathlib.Path('.env'), pathlib.Path(__file__).resolve().parents[1] / '.env']
    for p in paths:
        try:
            if p.exists():
                for line in p.read_text(encoding='utf-8').splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if '=' in line:
                        k, v = line.split('=', 1)
                        k = k.strip()
                        v = v.strip().strip('"').strip("'")
                        if k and v:
                            os.environ.setdefault(k, v)
        except Exception:
            pass

_load_env()

class OpenAIClient:
    def __init__(self, base_url=None, api_key=None, model=None, timeout=None, max_retries=3):
        self.base_url = base_url or os.environ.get('OPENAI_API_URL', 'https://api.openai.com/v1')
        self.api_key = api_key or os.environ.get('OPENAI_API_KEY', '')
        self.model = model or os.environ.get('OPENAI_API_MODEL', 'gpt-4o-mini')
        self.timeout = float(timeout or os.environ.get('OPENAI_API_TIMEOUT', '60'))
        self.max_retries = int(os.environ.get('OPENAI_API_MAX_RETRIES', str(max_retries)))
        self.session = requests.Session()

    def _endpoint(self):
        u = self.base_url.rstrip('/')
        if u.endswith('/chat/completions'):
            return u
        if u.endswith('/v1'):
            return u + '/chat/completions'
        return u + '/v1/chat/completions'

    def translate(self, text, target_lang='English'):
        if not self.api_key:
            return None
        payload = {
            'model': self.model,
            'messages': [
                {'role': 'system', 'content': f'Translate the content posted by the user into {target_lang} and keep the original format. Only return the translation result without any additional instructions or styles.'},
                {'role': 'user', 'content': text}
            ],
            'temperature': 0
        }
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        delay = 1.0
        for i in range(self.max_retries):
            try:
                r = self.session.post(self._endpoint(), headers=headers, data=json.dumps(payload), timeout=self.timeout)
                if r.status_code == 200:
                    d = r.json()
                    try:
                        return d['choices'][0]['message']['content'].strip()
                    except Exception:
                        return None
                if r.status_code in (429, 500, 502, 503, 504):
                    time.sleep(delay)
                    delay = min(delay * 2, 10)
                    continue
                return None
            except Exception:
                time.sleep(delay)
                delay = min(delay * 2, 10)
        return None
    
    def generate_solution(self, cve_id=None, vuln=None, advisory_text=None, target_lang='中文'):
        if not self.api_key:
            return None
        title = ''
        desc = ''
        sev = ''
        try:
            if isinstance(vuln, dict):
                title = str(vuln.get('title') or '')
                desc = str(vuln.get('description') or '')
                sev = str(vuln.get('level') or vuln.get('severity') or '')
        except Exception:
            pass
        cve = str(cve_id or (vuln.get('cve') if isinstance(vuln, dict) else '') or (vuln.get('nvdCve') if isinstance(vuln, dict) else '') or '').strip()
        context = []
        if cve:
            context.append(f'CVE: {cve}')
        if title:
            context.append(f'标题: {title}')
        if sev:
            context.append(f'严重性: {sev}')
        if desc:
            context.append(f'描述: {desc}')
        if advisory_text:
            context.append(f'相关处置建议: {str(advisory_text)}')
        ctx = '\n'.join(context).strip()
        payload = {
            'model': self.model,
            'messages': [
                {'role': 'system', 'content': f'你是网络安全修复建议专家。根据提供的漏洞信息与处置建议，生成该漏洞在企业环境中的修复建议。要求具体、可执行、步骤清晰，涵盖补丁或版本更新、配置加固、检测与响应、临时缓解与验证步骤。仅用{target_lang}返回纯文本修复建议，不要返回JSON或额外说明。'},
                {'role': 'user', 'content': ctx}
            ],
            'temperature': 0
        }
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        delay = 1.0
        for _ in range(self.max_retries):
            try:
                r = self.session.post(self._endpoint(), headers=headers, data=json.dumps(payload), timeout=self.timeout)
                if r.status_code == 200:
                    d = r.json()
                    try:
                        return d['choices'][0]['message']['content'].strip()
                    except Exception:
                        return None
                if r.status_code in (429, 500, 502, 503, 504):
                    time.sleep(delay)
                    delay = min(delay * 2, 10)
                    continue
                return None
            except Exception:
                time.sleep(delay)
                delay = min(delay * 2, 10)
        return None
    
    def generate_solution_with_advice(self, cve_id=None, vuln=None, advice_text=None, target_lang='中文'):
        return self.generate_solution(cve_id=cve_id, vuln=vuln, advisory_text=advice_text, target_lang=target_lang)

def is_empty(v):
    if v is None:
        return True
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return True
        if s.lower() == 'null':
            return True
    return False

