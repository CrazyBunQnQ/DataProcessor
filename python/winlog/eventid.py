import os
import csv
import re
from collections import defaultdict

# 定义存储事件文本的目录
directory_path = './input/'


# 解析单个事件内容的函数
def parse_event_content(content):
    # 为解析后的数据创建字典
    parsed_data = {
        'value': None,
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

    # 提取介于“message:”和下一次出现的“event:”或字符串末尾之间的消息
    message_match = re.search(r'message:(.*?)(?=event:|$)', content, re.DOTALL)
    if message_match:
        parsed_data['message'] = message_match.group(1).strip()

    return parsed_data


# 处理每个文件并提取事件的辅助函数
def process_file(file_path):
    # 从文件名中提取 Windows 版本
    windows_version = re.search(r'Win\d+', file_path).group(0)
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()

        # 将内容拆分为事件
        events = re.split(r'event:', content)

        # 处理每个事件匹配
        for event_content in events[1:]:  # 跳过第一个分割，因为它在第一个“事件：”之前
            event_dict = parse_event_content(event_content)
            event_dict['message'] = event_dict['message'].strip()
            event_dict['windows_version'] = windows_version

            # 生成事件字典
            yield event_dict


# 创建一个字典来存储事件，并以事件 ID 为键
events_by_id = defaultdict(dict)

# 遍历目录中的每个文件并处理事件
for filename in os.listdir(directory_path):
    file_path = os.path.join(directory_path, filename)
    if os.path.isfile(file_path):
        for event in process_file(file_path):
            event_id = event['value']
            existing_event = events_by_id[event_id]

            # 检查事件消息是否包含汉字并优先处理
            if 'message' in existing_event:
                if re.search('[\u4e00-\u9fff]', event['message']):
                    existing_event['message'] = event['message']
            else:
                existing_event['message'] = event['message']

            # 更新Windows版本列表
            if 'windows_version' in existing_event:
                existing_event['windows_version'] += f";{event['windows_version']}"
            else:
                existing_event['windows_version'] = event['windows_version']

            # 如果尚未设置剩余字段，请更新它们
            for field in ['version', 'opcode', 'channel', 'level', 'task', 'keywords']:
                if field not in existing_event:
                    existing_event[field] = event[field]

            # 将更新的事件存储回字典中
            events_by_id[event_id] = existing_event

# 写入 CSV 文件
csv_file_path = './parsed_events.csv'
fieldnames = ['value', 'version', 'opcode', 'channel', 'level', 'task', 'keywords', 'message', 'windows_version']
with open(csv_file_path, 'w', newline='', encoding='utf-8') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for event_id, event_data in events_by_id.items():
        event_data['value'] = event_id
        writer.writerow(event_data)

print(f'Events have been parsed and merged into {csv_file_path}')
