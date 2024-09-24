from suricata.desc_trans.trans.bot_factory import BaseBot

import json
import os

import requests

# Constants 文件省略
API_KEY = os.environ.get("YI_YAN_API_KEY")
SECRET_KEY = os.environ.get("YI_YAN_SECRET_KEY")


class YiyanBot(BaseBot):

    def get_access_token(self):
        """
        使用 AK，SK 生成鉴权签名（Access Token）
        :return: access_token，或是None(如果错误)
        """
        url = "https://aip.baidubce.com/oauth/2.0/token"
        params = {"grant_type": "client_credentials", "client_id": API_KEY, "client_secret": SECRET_KEY}
        return str(requests.post(url, params=params).json().get("access_token"))

    def ask_q(self, q: str, sid_cache: dict) -> dict:
        sid = self.get_sid(q)
        if sid in sid_cache:
            return {}
        msg = self.get_msg(q)
        url = "https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/completions?access_token=" + self.get_access_token()

        payload = json.dumps({
            "messages": [
                {
                    "role": "user",
                    'content': f"解释一下如下的 suricata 入侵检测规则，不用给出建议，直观解释一下即可，我需要展示给不懂工控安全的人员去看，我的要求是文字限制在 "
                               f"100~300字，且不要返回markdown格式，返回字符串即可，以 '此风险指的是' 为开头，返回内容不带双引号，规则如下：{q if len(msg) == 0 else msg}"
                }
            ]
        })
        headers = {
            'Content-Type': 'application/json'
        }

        response = requests.request("POST", url, headers=headers, data=payload)
        resp = json.loads(response.text)

        ans = {'sid': sid, 'result': resp['result']}
        return ans

    @staticmethod
    def get_seq() -> int:
        return 0


if __name__ == '__main__':
    y = YiyanBot()
    resp = y.ask_q(
        'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"AVTECH 软件 ActiveX SendCommand 方法缓冲区溢出尝试"; flow:established,to_client; content:"<OBJECT "; nocase; content:"classid"; nocase; distance:0; content:"clsid"; nocase; distance:0; content:"8214B72E-B0CD-466E-A44D-1D54D926038D"; nocase; distance:0; content:"SendCommand"; nocase; reference:url,zeroscience.mk/en/vulnerabilities/ZSL-2010-4934.php; reference:url,exploit-db.com/exploits/12294; classtype:attempted-user; sid:2011200; rev:4; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2010_07_30, deployment Perimeter, confidence High, signature_severity Major, tag ActiveX, updated_at 2019_09_27;)')

    with open("../desc2.dict", 'a', encoding='utf-8') as output:
        output.write(str(resp) + "\n")
