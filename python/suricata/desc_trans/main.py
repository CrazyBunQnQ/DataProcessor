import ast
from typing import Type

from tqdm import tqdm

from suricata.desc_trans.trans.bot_factory import BaseBot
from suricata.desc_trans.trans.openai_bot import OpenaiBot
from suricata.desc_trans.trans.tongyi_bot import TongyiBot
from suricata.desc_trans.trans.xinghuo_bot import XinghuoBot
from suricata.desc_trans.trans.yiyan_bot import YiyanBot

dict_cache = set()

bots = {}


def trans(bot_seq: int, i_file: str, o_file: str):
    b = bots.get(bot_seq)

    with open(i_file, "r", encoding='utf-8') as file:
        lines = file.readlines()
        for i in tqdm(range(len(lines))):
            line = lines[i]
            # 适配空行与注释行
            if len(line) == 0 or line == '\n' or line.startswith("#"):
                continue
            try:
                resp = b.ask_q(line, dict_cache)
                if len(resp) == 0:
                    continue
            except Exception as e:
                print(e)
                continue
            with open(o_file, 'a', encoding='utf-8') as output:
                output.write(str(resp) + "\n")


def init_dict_cache(i_files: list[str]):
    for i_file in i_files:
        with open(i_file, 'r', encoding='utf-8') as file:
            for line in file.readlines():
                try:
                    d = ast.literal_eval(line.strip())
                    if 'sid' in d:
                        dict_cache.add(d['sid'])
                except ValueError as e:
                    print(e.__cause__)
                    continue


class BotFactory:
    def __init__(self, bot: Type[BaseBot]) -> None:
        self.bot = bot

    def instance(self) -> BaseBot:
        return self.bot()


def init_bots():
    open_api = BotFactory(OpenaiBot).instance()
    bots[open_api.get_seq()] = open_api
    tong_yi = BotFactory(TongyiBot).instance()
    bots[tong_yi.get_seq()] = tong_yi
    xing_huo = BotFactory(XinghuoBot).instance()
    bots[xing_huo.get_seq()] = xing_huo
    yi_yan = BotFactory(YiyanBot).instance()
    bots[yi_yan.get_seq()] = yi_yan


if __name__ == '__main__':
    init_bots()
    init_dict_cache(["desc/desc.dict"])
    trans(0, "rules/csa.rules", "desc/desc.dict")
