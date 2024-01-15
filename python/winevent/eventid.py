import os
import csv
import re
from collections import defaultdict

# 定义存储事件文本的目录
directory_path = './input/'


# 解析单个事件内容的函数
def parse_event_content(from_name, content):
    # 为解析后的数据创建字典
    parsed_data = {
        'key': None,
        'value': None,
        'from': from_name,
        'version': None,
        'opcode': None,
        'channel': None,
        'level': None,
        'task': None,
        'keywords': None,
        'message': None
    }

    # Parse the data
    parsed_data['value'] = re.search(r'value: (.*)', content).group(1)
    parsed_data['version'] = re.search(r'version: (.*)', content).group(1)
    parsed_data['opcode'] = re.search(r'opcode: (.*)', content).group(1)
    parsed_data['channel'] = re.search(r'channel: (.*)', content).group(1)
    parsed_data['level'] = re.search(r'level: (.*)', content).group(1)
    parsed_data['task'] = re.search(r'task: (.*)', content).group(1)
    parsed_data['keywords'] = re.search(r'keywords: (.*)', content).group(1)
    # 计算 keywords 的 md5
    parsed_data['key'] = hashlib.md5((parsed_data['value'] + parsed_data['from'] + parsed_data['version'] + parsed_data['opcode'] + parsed_data['channel'] + parsed_data['level'] + parsed_data['task'] + parsed_data['keywords']).encode('utf-8')).hexdigest()

    # 提取介于“message:”和下一次出现的“event:”或字符串末尾之间的消息
    message_match = re.search(r'message:(.*?)(?=event:|$)', content, re.DOTALL)
    if message_match:
        parsed_data['message'] = message_match.group(1).strip()

    return parsed_data


# 处理每个文件并提取事件的辅助函数
def process_file(file_path):
    # 从文件名中截取最后一个 '_' 之前的部分
    from_name = file_path.rsplit('_', 1)[0]
    from_name = from_name.split('/')[-1]
    # 从文件名中提取 Windows 版本, 截取最后一个 '_' 到 '.' 之间的部分
    windows_version = file_path.split('_')[-1].split('.')[0]
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()

        # 将内容拆分为事件
        events = re.split(r'event:', content)

        # 处理每个事件匹配
        for event_content in events[1:]:  # 跳过第一个分割，因为它在第一个“事件：”之前
            try:
                event_dict = parse_event_content(from_name, event_content)
                event_dict['message'] = event_dict['message'].strip()
            except Exception:
                continue
            # 如果 message 是空的则跳过
            if not event_dict['message']:
                continue
            event_dict['windows_version'] = windows_version

            # 生成事件字典
            yield event_dict


# 创建一个字典来存储事件，并以事件 ID 为键
events_by_key = defaultdict(dict)

# 遍历目录中的每个文件并处理事件
for filename in os.listdir(directory_path):
    file_path = os.path.join(directory_path, filename)
    if os.path.isfile(file_path):
        for event in process_file(file_path):
            event_key = hashlib.md5((event['value'] + event['from'] + event['version'] + event['opcode'] + event['channel'] + event['level'] + event['task'] + event['keywords']).encode('utf-8')).hexdigest()
            existing_event = events_by_key[event_key]
            # 判断 events_by_id 中是否包含 event_id
            if existing_event and event['message'] != existing_event['message'] and event['windows_version'] != 'Windows2016' and existing_event['windows_version'] != 'Windows2016':
                if event['message'] != existing_event['message'] and re.search('[\u4e00-\u9fff]', event['message']) and re.search('[\u4e00-\u9fff]', existing_event['message']):
                    print(f"event_id: {event_key}")
                    print(f"pre event: {existing_event['message']}")
                    print(f"cur event: {event['message']}")
                    print("------------------")

            # 检查事件消息是否包含汉字并优先处理
            if 'message' in existing_event:
                if re.search('[\u4e00-\u9fff]', event['message']):
                    existing_event['message'] = event['message']
            else:
                existing_event['message'] = event['message']

            # 更新Windows版本列表
            if 'windows_version' in existing_event:
                # 如果不包含则追加
                if event['windows_version'] not in existing_event['windows_version']:
                    existing_event['windows_version'] += f";{event['windows_version']}"
            else:
                existing_event['windows_version'] = event['windows_version']

            # 如果尚未设置剩余字段，请更新它们
            for field in ['value', 'from', 'version', 'opcode', 'channel', 'level', 'task', 'keywords']:
                if field not in existing_event:
                    existing_event[field] = event[field]

            # 将更新的事件存储回字典中
            events_by_key[event_key] = existing_event

# 写入 CSV 文件
csv_file_path = './parsed_events.csv'
fieldnames = ['key', 'value', 'from', 'version', 'opcode', 'channel', 'level', 'task', 'keywords', 'message', 'windows_version']
with open(csv_file_path, 'w', newline='', encoding='utf-8') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for event_key, event_data in events_by_key.items():
        event_data['key'] = event_key
        # event_data['value'] = event_key
        writer.writerow(event_data)

print(f'Events have been parsed and merged into {csv_file_path}')
