import os
from suricata.desc_trans.trans.bot_factory import BaseBot

from sparkai.llm.llm import ChatSparkLLM, ChunkPrintHandler
from sparkai.core.messages import ChatMessage

# Constants 文件省略
APP_ID = os.environ.get("SPARKAI_APP_ID")
API_SECRET = os.environ.get("SPARKAI_API_SECRET")
API_KEY = os.environ.get("SPARKAI_API_KEY")
spark = None


class XinghuoBot(BaseBot):
    """
        星火次数限制 10 万条（token限制）
        pip install --upgrade spark_ai_python
    """

    def get_access_token(self):
        if spark is None:
            self.spark = ChatSparkLLM(
                spark_api_url='wss://spark-api.xf-yun.com/v3.5/chat',
                spark_app_id=APP_ID,
                spark_api_key=API_KEY,
                spark_api_secret=API_SECRET,
                spark_llm_domain='generalv3.5',
                streaming=False,
            )

    def ask_q(self, q: str, sid_cache: dict) -> dict:
        sid = self.get_sid(q)
        if sid in sid_cache:
            return {}
        msg = self.get_msg(q)
        self.get_access_token()

        messages = [ChatMessage(
            role="user",
            content=f"解释一下如下的 suricata 入侵检测规则，不用给出建议，直观解释一下即可，我需要展示给不懂工控安全的人员去看，我的要求是文字限制在 "
                    f"100~300字，且不要返回markdown格式，返回字符串即可，以 '此风险指的是' 为开头，返回内容不带双引号，规则如下：{q if len(msg) == 0 else msg}"
        )]
        handler = ChunkPrintHandler()
        resp = self.spark.generate([messages], callbacks=[handler])

        generation = resp.generations[0][0]
        ans = {'sid': sid, 'result': generation.text}
        return ans

    @staticmethod
    def get_seq() -> int:
        return 1


if __name__ == '__main__':
    y = XinghuoBot()
    resp = y.ask_q(
        'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"AVTECH 软件 ActiveX SendCommand 方法缓冲区溢出尝试"; flow:established,to_client; content:"<OBJECT "; nocase; content:"classid"; nocase; distance:0; content:"clsid"; nocase; distance:0; content:"8214B72E-B0CD-466E-A44D-1D54D926038D"; nocase; distance:0; content:"SendCommand"; nocase; reference:url,zeroscience.mk/en/vulnerabilities/ZSL-2010-4934.php; reference:url,exploit-db.com/exploits/12294; classtype:attempted-user; sid:2011200; rev:4; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2010_07_30, deployment Perimeter, confidence High, signature_severity Major, tag ActiveX, updated_at 2019_09_27;)')

    with open("../desc3.dict", 'a', encoding='utf-8') as output:
        output.write(str(resp) + "\n")
