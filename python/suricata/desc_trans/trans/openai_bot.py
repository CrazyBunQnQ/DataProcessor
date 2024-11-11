import json
import os
import time

import requests

from suricata.desc_trans.trans.bot_factory import BaseBot

# 环境变量读取 API Key
API_KEY = os.environ.get("OPENAI_API_KEY")
# https://api.openai.com
API_URL = os.environ.get("OPENAI_API_URL")
if API_URL is None:
    API_URL = "https://api.openai.com"


class OpenaiBot(BaseBot):
    def get_access_token(self):
        pass

    def ask_q(self, q: str, sid_cache: dict, role: str = None, model: str = "gpt-4o-mini") -> dict:
        """
        :param q: 对话
        :param model: 模型-默认 gpt-4o-mini
        :param role: 系统角色定义-默认 None
        :return:
        """
        sid = self.get_sid(q)
        if sid in sid_cache:
            return {}
        # time.sleep(45) # 白嫖的 api 建议加上延迟
        msg = self.get_msg(q)
        headers = {
            "Content-Type": "application/json;charset=UTF-8",
            "Authorization": f'Bearer {API_KEY}'
        }
        payload = {
            "model": model,
            "messages": [
                {
                    "role": "user",
                    'content': f"用中文解释一下如下的 suricata 入侵检测规则，不用给出建议，直观解释一下即可，我需要展示给不懂工控安全的人员去看，我的要求是文字限制在 "
                               f"100~300字，且不要返回markdown格式，返回字符串即可，以 '此风险指的是' 为开头，返回内容不带双引号，规则如下：{q if len(msg) == 0 else msg}"
                }
            ]
        }
        # 若 role 不为 None 则在 payload.messages 中添加元素
        if role is not None:
            payload['messages'].insert(0, {
                "role": "system",
                "content": role
            })
        response = requests.post(f'{API_URL}/v1/chat/completions', headers=headers, json=payload)
        if response.status_code == 200:
            # 转为 json 格式
            resp = json.loads(response.text)
            content = resp['choices'][0]['message']['content']
            print(content)
            ans = {'sid': sid, 'result': content}
            return ans
        elif response.status_code == 429:
            print("代理节点已达到每24小时发送信息的限制。请更换代理节点后再试。")
            # 转为 json 格式
            return None, json.loads(response.text)
        elif response.status_code == 500 and ('captcha' in response.text or 'detected' in response.text):
            print("需要进行人机验证才能够正常使用。。")
            return {}
        elif response.status_code == 500 or response.status_code == 504 or response.status_code == 403:
            print(f"Error: {response.status_code} —— {response.text}")
            time.sleep(30)
            return {}
        else:
            print(f"Error: {response.status_code} —— {response.text}")
            return {}

    @staticmethod
    def get_seq() -> int:
        return 0


if __name__ == '__main__':
    y = OpenaiBot()
    resp = y.ask_q(
        '一句话解释 suricata 规则的作用: `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"AVTECH 软件 ActiveX SendCommand 方法缓冲区溢出尝试"; flow:established,to_client; content:"<OBJECT "; nocase; content:"classid"; nocase; distance:0; content:"clsid"; nocase; distance:0; content:"8214B72E-B0CD-466E-A44D-1D54D926038D"; nocase; distance:0; content:"SendCommand"; nocase; reference:url,zeroscience.mk/en/vulnerabilities/ZSL-2010-4934.php; reference:url,exploit-db.com/exploits/12294; classtype:attempted-user; sid:2011200; rev:4; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2010_07_30, deployment Perimeter, confidence High, signature_severity Major, tag ActiveX, updated_at 2019_09_27;)`',
        "你是一个专业的网络安全入侵检测领域翻译 API 接口，请结合你的专业知识将我发给你的的英文翻译成中文。注意: 1. 只是翻译文本不要做任何解释; 2. 人名、团队名、公司名及文件名不做翻译; 3. 众所周知的简称需要翻译(例如 RCE 是远程代码执行，Payload 是攻击载荷，Exploit 是利用，); 将翻译结果按照以下 json 格式返回给我：\n\n{\"translatedText\": \"翻译结果\"}\n还要注意不要返回无效的转义字符。"
    )
    print(resp)
