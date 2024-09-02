'''
Module to process .rules files containing the word 'exploit' and update messages based on translation.
'''
import os
import re

from translate import translate_text

exclude_file_list = ['emerging-deleted.rules', 'emerging-info.rules', 'emerging-icmp_info.rules', 'tor.rules']
file_list = ['emerging-exploit.rules', 'emerging-coinminer.rules', 'emerging-worm.rules']
classtype_list = ['command-and-control', 'coin-mining', 'credential-theft', 'successful-recon-largescale',
                  'successful-dos', 'non-standard-protocol', 'attempted-recon', 'web-application-attack',
                  'trojan-activity', 'unsuccessful-user', 'successful-user', 'successful-admin', 'shellcode-detect',
                  'attempted-user', 'attempted-admin']
keywords = ['mitre_', 'attack_target']
exclude_keywords = []
# 定义 Set
portVars = set()

regex = re.compile(r'\s*alert [^\(]*\(msg:"([^"]+)";.*\)')
classtype_regex = re.compile(r'\bclasstype:(\S+);')
replacements = {
    r'^ET EXPLOIT_KIT\s*': '',
    r'^ET EXPLOIT\s*': '',
    r'^ET ACTIVEX\s*': '',
    r'^ET ADWARE_PUP\s*': '',
    r'^ET COINMINER\s*': '',
    r'^ET CURRENT_EVENTS\s*': '',
    r'^ET HUNTING\s*': '',
    r'^ET INFO\s*': '',
    r'^ET CNC\s*': '',
    r'^GPL EXPLOIT\s*': '',
    r'^DRIVEBY\s*': '',
    r'\[NCC GROUP\]\s*': '',
    r'\[PT Security\]\s*': '',
    r'\[401TRG\]\s*': '',
    r'\[Fireeye\]\s*': '',
    r'\[PTsecurity\]\s*': '',
    r'\[eSentire\]\s*': '',
    r'\[TW\]\s*': '',
    r'\[PwnedPiper\]\s*': '',
    r'\[Rapid7\]\s*': '',
    r'\[TGI\]\s*': '',
    r'\[ANY\.RUN\]\s*': '',
    r'\[ConnectWise CRU\]\s*': '',
    r'\[Abuse\.ch\]\s*': '',
    r'\[GIGAMON_ATR\]\s*': '',
    r'\[PwC CTD\] -- MultiGroup -\s*': '',
    r'^ET (\w+)\s*': r'\1 ',
    r'^CNC (\w+)\s*': r'\1 ',
    r'^GPL (\w+)\s*': r'\1 ',
    r'^ATTACK_RESPONSE\s*': 'ATTACK RESPONSE ',
    r'^DYNAMIC_DNS\s*': 'DYNAMIC DNS ',
    r'^MOBILE_MALWARE\s*': 'MOBILE MALWARE ',
    r'^WEB_SPECIFIC_APPS\s*': '',
    r'^WEB_SERVER\s*': 'WEB SERVER ',
    r'^WEB_CLIENT\s*': 'WEB CLIENT '
}


def process_files():
    """
    Process all .rules files in the 'rules' directory that contain the word 'exploit'.
    """
    for root, dirs, files in os.walk('rules'):
        for file in files:
            if file in exclude_file_list or not file.endswith('.rules'):
                print(f'Skipping {file}...')
                continue
            elif file in file_list:
                print(f'Processing {file}...')
                with open("csa.rules", "a", encoding='utf-8') as output:
                    output.write(f'\n# {file}\n')
                process_file(os.path.join(root, file), True)
            else:
                print(f'analysis {file}...')
                with open("csa.rules", "a", encoding='utf-8') as output:
                    output.write(f'\n# {file}\n')
                process_file(os.path.join(root, file), False)


def process_file(filepath, full_file):
    """
    Read a .rules file, extract messages, translate them, and write the results to csa.rules.
    """
    with open(filepath, 'r', encoding='utf-8') as file:
        lines = file.readlines()
    with open("csa.rules", "a", encoding='utf-8') as output:
        for line in lines:
            if not line.strip().startswith('#'):
                match = regex.search(line)
                # 从 line 中提取 classtype 字段
                classtype_match = classtype_regex.search(line)
                if not full_file and classtype_match:
                    classtype = classtype_match.group(1)
                if any(keyword in line for keyword in exclude_keywords):
                    continue
                # 如果匹配到，则直接添加规则, 否则继续判断若全文添加或属于指定类型或包含指定关键字则添加规则
                if match and (full_file or classtype in classtype_list or any(keyword in line for keyword in keywords)):
                    # 从 line 中提取所有 \$\w+_PORTS
                    ports = re.findall(r'\$(\w+_PORTS)', line)
                    # 如果有则添加每一个匹配到的名称到 portVars 中
                    if ports:
                        portVars.update(ports)
                    original_msg = match.group(1)
                    # 删除开头的 'ET EXPLOIT ' 或 'GPL EXPLOIT '
                    original_simple_msg = original_msg
                    for pattern, replacement in replacements.items():
                        original_simple_msg = re.sub(pattern, replacement, original_simple_msg, flags=re.IGNORECASE)

                    translated_msg = translate_text(original_simple_msg)
                    modified_line = line.replace(f'msg:"{original_msg}"', f'msg:"{translated_msg}"')
                    output.write(modified_line)
        if portVars:
            print(f'务必在 suricata 配置文件中(/platform/appconf/dpdk_release.yaml)配置以下端口:  {portVars}')
