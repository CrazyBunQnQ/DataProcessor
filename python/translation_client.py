import os
import pathlib
import time
import urllib.parse
import requests
try:
    from .openai_client import OpenAIClient
except Exception:
    from openai_client import OpenAIClient

def _load_env():
    base = pathlib.Path(__file__).resolve()
    paths = [
        pathlib.Path('.env'),
        base.parents[1] / '.env',
        base.parent / '.env',
        base.parent / 'cve' / '.env'
    ]
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

class TranslationClient:
    def __init__(self):
        self.provider = (os.environ.get('TRANSLATE_PROVIDER', 'ai') or 'ai').strip().lower()
        self.session = requests.Session()
        self.ai = OpenAIClient() if self.provider == 'ai' else None
        self.timeout = float(os.environ.get('GOOGLE_TRANSLATE_TIMEOUT', '10'))
        self.max_retries = int(os.environ.get('GOOGLE_TRANSLATE_MAX_RETRIES', '3'))

    def can_translate(self):
        if self.provider == 'ai':
            return bool(self.ai and self.ai.api_key)
        return True

    def translate(self, text, target_lang='English'):
        s = str(text)
        if self.provider == 'ai':
            return self.ai.translate(s, target_lang or 'English')
        return self._google_translate(s, target_lang)

    def _to_google_lang(self, target_lang):
        t = (target_lang or '').strip().lower()
        if t in ('en', 'english'):
            return 'en'
        if t in ('zh', 'chinese', 'zh-cn', 'zh-hans', 'cn'):
            return 'zh'
        if len(t) == 2:
            return t
        return 'en'

    def _google_translate(self, text, target_lang):
        base_url = 'https://translate.googleapis.com/translate_a/single'
        q = urllib.parse.quote(text)
        tl = self._to_google_lang(target_lang)
        params = {
            'client': 'gtx',
            'sl': 'auto',
            'tl': tl,
            'dt': 't',
            'q': q
        }
        url = f"{base_url}?client={params['client']}&sl={params['sl']}&tl={params['tl']}&dt={params['dt']}&q={params['q']}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0'
        }
        delay = 1.0
        for _ in range(self.max_retries):
            try:
                r = self.session.get(url, headers=headers, timeout=self.timeout)
                if r.status_code == 200:
                    try:
                        d = r.json()
                    except Exception:
                        d = None
                    if d:
                        try:
                            return ''.join([item[0] for item in d[0]])
                        except Exception:
                            return None
                time.sleep(delay)
                delay = min(delay * 2, 10)
            except Exception as e:
                print(f'Google translate error: {str(e)}; retry in {delay}s')
                time.sleep(delay)
                delay = min(delay * 2, 10)
        return None
