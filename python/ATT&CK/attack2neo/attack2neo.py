#!/usr/bin/env python3

import argparse
import json
import re
import sys
import time
from datetime import datetime

import requests
from py2neo import Graph, Node, Relationship, NodeMatcher

LibreTranslateAPI = "your libretranslate api url"
OpenAIUrl = "https://api.openai.com/v1/chat/completions"
OpenAIKey = "sk-xxxx"
translate_cache = {}

# 提取翻译结果的正则表达式模式
pattern = r'["\']translatedText["\']: ["\']([^}]+)'


def load_cache():
    global translate_cache
    try:
        # 如果本地文件存在则尝试读取上次保存的翻译缓存
        with open('translate_cache.json', 'r', encoding='utf-8') as f:
            translate_cache = json.load(f)
    except Exception as e:
        print('读取翻译缓存失败...')


def save_cache():
    global translate_cache
    with open('translate_cache.json', 'w', encoding='utf-8') as f:
        json.dump(translate_cache, f, ensure_ascii=False, indent=4)


load_cache()
translate_count = 0


# -----------------------------------------------------------------
# BUILD_LABEL
# -----------------------------------------------------------------
def build_label(txt):
    if txt.startswith('intrusion-set'):
        return 'Group'
    if txt.startswith('malware'):
        return 'Software'
    if txt.startswith('tool'):
        return 'Tool'
    if txt.startswith('attack-pattern'):
        return 'Technique'
    if txt.startswith('course-of-action'):
        return 'Mitigations'
    if txt.startswith('campaign'):
        return 'Campaign'
    if txt.startswith('x-mitre-tactic'):
        return 'Tactic'
    return 'Unknown'


# -----------------------------------------------------------------
# Translate Text
# -----------------------------------------------------------------
def translate_text(text, source_lang='en', target_lang='zh', engine='OpenAI', retry=True):
    if len(text) < 2:
        return text
    # 检查缓存
    if text in translate_cache:
        return translate_cache[text]

    if engine == 'OpenAI':
        return translate_text_by_openai(text, retry)
    else:
        return translate_text_by_libre_translate(text, source_lang, target_lang)


def translate_text_by_openai(text, retry=True):
    global translate_count
    global translate_cache
    headers = {
        "Content-Type": "application/json;charset=UTF-8",
        "Authorization": OpenAIKey
    }
    payload = {
        "model": "gpt-3.5-turbo",
        "messages": [
            {
                "role": "system",
                "content": "你是一个专业的网络安全领域翻译 API 接口，请结合你的专业知识将我发给你的 ATT&CK 框架相关的英文文本翻译成中文。注意保持原有格式，且专有名词及链接不做翻译, 并按照以下 json 格式返回给我：\n\n{\"translatedText\": \"翻译结果\"}\n还要注意不要返回无效的转义字符。"
            },
            {
                "role": "user",
                "content": text
            }
        ]
    }

    while True:
        try:
            # 检查缓存
            if text in translate_cache:
                return translate_cache[text]
            response = requests.post(OpenAIUrl, headers=headers, json=payload)
            if response.status_code == 200:
                response_content = response.text
                # 转为 json 格式
                response_content = json.loads(response_content)
                # 获取 .get('choices', []).get('0', {}).get('message', {}).get('content', ''))
                response_content = response_content.get('choices', [])
                response_content = response_content[0]
                response_content = response_content.get('message', {})
                response_content = response_content.get('content', '')
                # 如果返回的内容中包含 '`' 则替换为 ''
                if response_content.find('```json') != -1:
                    response_content = response_content.replace('```json', '')
                if response_content.find('```') != -1:
                    response_content = response_content.replace('```', '')
                if response_content.find('`') != -1:
                    response_content = response_content.replace('`', '')
                translated_text = ''
                try:
                    translated_text = json.loads(response_content, strict=False)
                    translated_text = translated_text.get('translatedText', '')
                except Exception:
                    # 根据正则表达式 ['"]translatedText['"]: ['"] 从 response_content 截取 translatedText 的内容
                    match = re.search(pattern, response_content)
                    if match:
                        translated_text = match.group(1)
                        # 删除最后的所有空字符
                        translated_text = translated_text.rstrip()[:-1]
                        print("正则截取...")
                if translated_text == '':
                    if retry:
                        print(f"翻译失败: {text} - {response_content}，将在 30 秒后重试...")
                        time.sleep(30)
                        load_cache()
                    else:
                        translate_cache[text] = text
                        save_cache()
                        translate_count += 1
                        time.sleep(5)
                        return text
                else:
                    translate_cache[text] = translated_text  # 存储翻译结果到缓存
                    save_cache()
                    translate_count += 1
                    time.sleep(5)
                    return translated_text
            elif response.status_code == 429:
                print("代理节点已达到每24小时发送信息的限制。请更换代理节点后再试。")
                exit(1)
            elif response.status_code == 500 or response.status_code == 504 or response.status_code == 403:
                print(f"Error: {response.status_code}, 10 秒后重试")
                time.sleep(5)
            else:
                print(f"Error: {response.status_code}")
                time.sleep(30)
        except Exception:
            print(f"请求失败: {text}，将在 3 秒后重试...")
            time.sleep(3)


def translate_text_by_libre_translate(text, source_lang='en', target_lang='zh'):
    global translate_count
    headers = {
        "Content-Type": "application/json;charset=UTF-8"
    }
    payload = {
        "q": text,
        "source": source_lang,
        "target": target_lang
    }

    while True:
        try:
            response = requests.post(LibreTranslateAPI, headers=headers, json=payload)
            if response.status_code == 200:
                translated_text = response.json().get('translatedText', '')
                translate_cache[text] = translated_text  # 存储翻译结果到缓存
                translate_count += 1
                return translated_text
            else:
                return f"Error: {response.status_code}"
        except Exception:
            print(f"请求失败，将在 10 秒后重试...")
            time.sleep(10)


def translate_obj(o):
    if args.localization == 'en':
        return
    if o.get('name'):
        # 软件名、团队名等翻译困难的名称若翻译失败后不重试
        name = translate_text(o['name'], 'en', args.localization, "OpenAI", o.get('type') not in ['malware', 'intrusion-set', 'tool'])
        if len(name) != 0:
            o['name'] = o['name'] + '(' + name + ')'
    if o.get('description'):
        description = translate_text(o['description'], 'en', args.localization)
        if len(description) != 0:
            o['description'] = description
    if obj.get('x_mitre_detection'):
        detection = translate_text(o['x_mitre_detection'], 'en', args.localization)
        if len(detection) != 0:
            o['x_mitre_detection'] = detection


# -----------------------------------------------------------------
# BUILD ALIASES
# -----------------------------------------------------------------
def build_objects(obj):
    label = build_label(obj['type'])

    # add properties
    props = {'name': obj['name'], 'id': obj['id'], 'type': obj['type']}
    if obj.get('description'):
        props['description'] = obj['description']
        # cypher.cypher_escape( obj['description'] )
    if obj.get('created'):
        props['created'] = obj['created']
    if obj.get('modified'):
        props['modified'] = obj['modified']
        props['updateTimestamp'] = int(datetime.fromisoformat(obj['modified'].rstrip("Z")).timestamp() * 1000)
    if obj.get('x_mitre_version'):
        props['version'] = obj['x_mitre_version']
    if obj.get('kill_chain_phases') and len(obj['kill_chain_phases']) > 0:
        tactics_phase = obj['kill_chain_phases']
        props['killChainName'] = tactics_phase[0]['kill_chain_name']
        # 收集所有的 phase_name 到列表中
        props['tacticsPhaseName'] = [phase['phase_name'] for phase in tactics_phase]
    if obj.get('aliases'):
        props['aliases'] = obj['aliases']
    elif obj.get('x_mitre_aliases'):
        props['aliases'] = obj['x_mitre_aliases']
    if obj.get('x_mitre_platforms'):
        props['platforms'] = obj['x_mitre_platforms']
    if obj.get('labels'):
        props['labels'] = obj['labels']
    if obj.get('x_mitre_deprecated'):
        props['deprecated'] = obj['x_mitre_deprecated']
    if obj.get('x_mitre_detection'):
        props['detection'] = obj['x_mitre_detection']
    if obj.get('x_mitre_domains'):
        props['domains'] = obj['x_mitre_domains']
    if obj.get('x_mitre_is_subtechnique'):
        props['isSubtechnique'] = obj['x_mitre_is_subtechnique']
    if obj.get('x_mitre_data_sources'):
        props['dataSources'] = obj['x_mitre_data_sources']
    if obj.get('x_mitre_shortname'):
        props['shortName'] = obj['x_mitre_shortname']
    if obj.get('revoked'):
        props['revoked'] = obj['revoked']
    if obj.get('external_references'):
        external_references = obj['external_references']
        for reference in external_references:
            if 'external_id' in reference:
                props['mitreUrl'] = reference['url']
                props['mitreId'] = reference['external_id']
                break  # 找到后就可以退出循环

    # create node for the group
    node_main = Node('BaseNode', 'KnowledgeNode', 'Neo4jAttckBaseNode', label, **props)
    # merge node to graph
    graph.merge(node_main, label, 'name')
    print('%s: "%s"' % (label, obj['name']), end='') if dbg_mode else None

    # dealing with aliases
    if obj.get('aliases'):
        aliases = obj['aliases']
    elif obj.get('x_mitre_aliases'):
        aliases = obj['x_mitre_aliases']
    else:
        aliases = None
    if aliases:
        for alias in aliases:
            name = translate_text(alias, 'en', args.localization, "OpenAI", obj['type'] not in ['malware', 'intrusion-set', 'tool'])
            if len(name) != 0 and name != alias:
                alias = alias + '(' + name + ')'
            # 建立别名关系
            if alias != obj['name']:
                node_alias = Node('BaseNode', 'KnowledgeNode', 'AttckAlias', name=alias, type=obj['type'])
                relation = Relationship.type('alias')
                graph.merge(relation(node_main, node_alias), label, 'name')
                print(' -[alias]-> "%s"' % alias, end='') if dbg_mode else None
    print() if dbg_mode else None


# -----------------------------------------------------------------
# BUILD RELATIONS
# -----------------------------------------------------------------
def build_relations(obj):
    if not gnames.get(obj['source_ref']):
        return
    if not gnames.get(obj['target_ref']):
        return

    m = NodeMatcher(graph)

    source = m.match(build_label(obj['source_ref']), name=gnames[obj['source_ref']]).first()
    target = m.match(build_label(obj['target_ref']), name=gnames[obj['target_ref']]).first()

    # source = Node( build_label(obj['source_ref']), name=gnames[obj['source_ref']], id=obj['source_ref'] )
    # target = Node( build_label(obj['target_ref']), name=gnames[obj['target_ref']], id=obj['target_ref'] )
    # relation = Relationship.type(obj['relationship_type'])
    # graph.merge(relation(source, target), build_label(obj['source_ref']), 'name')
    relation = Relationship(source, 'AttckRelation', target, caption=obj['relationship_type'],
                            description=obj['description'] if obj.get('description') else None)
    graph.merge(relation, build_label(obj['source_ref']), 'name')
    print('Relation: "%s" -[%s]-> "%s"' % (
        gnames[obj['source_ref']], obj['relationship_type'], gnames[obj['target_ref']])) if dbg_mode else None


# -----------------------------------------------------------------
# MAIN
# -----------------------------------------------------------------

#
# set command-line arguments and parsing options
parser = argparse.ArgumentParser()
parser.add_argument('-d', '--debug', help='enter debug mode', default=False, action='store_true')
parser.add_argument('-f', help='input file name', metavar='<filename>', action='store', required=True)
parser.add_argument('-g', '--groups', help='import Groups objects (type:intrusion-set)', default=False,
                    action='store_true')
parser.add_argument('-s', '--softwares', help='import Softwares objects (type:malware)', default=False,
                    action='store_true')
parser.add_argument('-o', '--tools', help='import Tools objects (type:tool)', default=False, action='store_true')
parser.add_argument('-t', '--techniques',
                    help='import Techniques objects (type:attack-pattern and type:course-of-action)', default=False,
                    action='store_true')
parser.add_argument('-r', '--relations', help='import Relations objects (type:relationship)', default=False,
                    action='store_true')
parser.add_argument('-u', '--unknown', help='import other objects', default=True, action='store_true')
parser.add_argument('-l', '--localization', help='translated into local languages', default='zh',
                    action='store', required=False)
parser.add_argument('-e', '--engine', help='translation engine (OpenAI, LibreTranslate)', default='OpenAI',
                    action='store', required=False)
args = parser.parse_args()

#
# checks arguments and options
dbg_mode = True if args.debug else None
json_file = args.f if args.f else None

#
# load JSON data from file
try:
    with open(json_file) as fh:
        data = json.load(fh)
    fh.close()
except Exception as e:
    sys.stderr.write('[ERROR] reading configuration file %s\n' % json_file)
    sys.stderr.write('[ERROR] %s\n' % str(e))
    sys.exit(1)

#
# open graph connection
graph_bolt = "bolt://192.168.1.77:7687"
graph_auth = ("neo4j","pwd")

graph = Graph(graph_bolt, auth=graph_auth)

# 
# Delete existing nodes and edges
# graph.delete_all()

# 
# Global names
gnames = {}

# 
# Walk through JSON objects to create nodes
for obj in data['objects']:

    # if JSON object is about Groups
    if args.groups and obj['type'] == 'intrusion-set':
        translate_obj(obj)
        gnames[obj['id']] = obj['name']
        build_objects(obj)
        continue

    # if JSON object is about Softwares
    if args.softwares and obj['type'] == 'malware':
        translate_obj(obj)
        gnames[obj['id']] = obj['name']
        build_objects(obj)
        continue

    # if JSON object is about Tools
    if args.tools and obj['type'] == 'tool':
        translate_obj(obj)
        gnames[obj['id']] = obj['name']
        build_objects(obj)
        continue

    # if JSON object is about Techniques
    if args.techniques and obj['type'] == 'attack-pattern':
        translate_obj(obj)
        gnames[obj['id']] = obj['name']
        build_objects(obj)
        continue
    if args.techniques and obj['type'] == 'course-of-action':
        translate_obj(obj)
        gnames[obj['id']] = obj['name']
        build_objects(obj)
        continue
    # 活动相关
    if args.unknown and obj['type'] == 'campaign':
        translate_obj(obj)
        build_objects(obj)
        continue
    # 策略相关
    if obj['type'] == 'x-mitre-tactic':
        translate_obj(obj)
        build_objects(obj)
        continue
    if (obj['type'] == 'identity' or obj['type'] == 'marking-definition' or obj['type'] == 'x-mitre-collection'
            or obj['type'] == 'x-mitre-data-component' or obj['type'] == 'x-mitre-asset'
            or obj['type'] == 'x-mitre-data-source' or obj['type'] == 'x-mitre-matrix'
            or obj['type'] == 'relationship'):
        continue
    print("other debug")
    # label = build_label(obj['type'])
    # node_main = Node(label, name=obj['name'], id=obj['id'])
    # graph.merge(node_main,label,'name')
    # print('%s: "%s"' % (label,obj['name']) ) if dbg_mode else None

# 
# Walk through JSON objects to create edges
for obj in data['objects']:

    # if JSON object is about Relationships
    if args.relations and obj['type'] == 'relationship':
        build_relations(obj)

print("翻译次数: " + str(translate_count))
# 保存翻译缓存为本地 json 文件
if args.engine != 'OpenAI':
    save_cache()
# End
