#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
威胁URL数据处理器
从 https://myip.ms/files/blacklist/general/latest_blacklist.txt 获取威胁IP数据
并转换为指定的JSON格式
"""

import requests
import json
import re
from datetime import datetime
import time
import os
import urllib3
import zipfile
import io

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ThreatURLProcessor:
    def __init__(self):
        # 全量 https://myip.ms/files/blacklist/general/full_blacklist_database.zip
        # 最新增量 https://myip.ms/files/blacklist/general/latest_blacklist.txt
        self.source_url = "https://myip.ms/files/blacklist/general/full_blacklist_database.zip"
        self.base_url = "https://myip.ms/browse/blacklist"
        # 生成带日期的输出文件名
        current_date = datetime.now().strftime("%Y%m%d")
        self.output_file = f"threat_urls_incremental_{current_date}.json"
        self.existing_data_file = "SSAThreatURL.json"
        self.existing_data = {}  # 存储已有的完整数据记录，以IP为键
        
    def fetch_blacklist_data(self):
        """
        从源URL获取黑名单数据；支持 ZIP 全量数据解压
        """
        try:
            print(f"正在从 {self.source_url} 获取数据...")
            # 添加SSL验证跳过和用户代理
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            # 全量 ZIP 文件可能较大，适当增加超时
            response = requests.get(self.source_url, timeout=120, verify=False, headers=headers)
            response.raise_for_status()
            print("数据获取成功")

            # 如果是ZIP文件，进行解压读取TXT
            if self.source_url.lower().endswith('.zip'):
                try:
                    with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
                        # 尝试找到第一个TXT文件
                        txt_names = [n for n in zf.namelist() if n.lower().endswith('.txt')]
                        if not txt_names:
                            print("ZIP包内未找到TXT文件")
                            return None
                        target_name = txt_names[0]
                        print(f"正在解压读取: {target_name}")
                        with zf.open(target_name) as f:
                            raw_bytes = f.read()
                            try:
                                return raw_bytes.decode('utf-8')
                            except UnicodeDecodeError:
                                # 兼容可能的编码差异
                                return raw_bytes.decode('latin-1')
                except zipfile.BadZipFile:
                    print("ZIP文件格式错误，无法解压")
                    return None
            else:
                # 非ZIP：直接返回文本内容
                return response.text
        except requests.RequestException as e:
            print(f"获取数据失败: {e}")
            return None
    
    def load_existing_data(self):
        """
        读取已有的威胁URL数据文件，存储完整数据记录用于更新
        """
        if not os.path.exists(self.existing_data_file):
            print(f"已有数据文件 {self.existing_data_file} 不存在，将创建新文件")
            return
        
        try:
            print(f"正在读取已有数据文件: {self.existing_data_file}")
            with open(self.existing_data_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            if 'ip' in data:
                                self.existing_data[data['ip']] = data
                        except json.JSONDecodeError as e:
                            print(f"解析第 {line_num} 行JSON数据失败: {e}")
                            continue
            
            print(f"已加载 {len(self.existing_data)} 个已有数据记录")
            
        except Exception as e:
            print(f"读取已有数据文件失败: {e}")
            self.existing_data = {}  # 重置为空字典
    
    def parse_date_to_timestamp(self, date_str):
        """
        将日期字符串转换为时间戳（毫秒）
        输入格式: 2025-10-19
        """
        try:
            dt = datetime.strptime(date_str, "%Y-%m-%d")
            # 转换为毫秒时间戳
            timestamp_ms = int(dt.timestamp() * 1000)
            return timestamp_ms
        except ValueError as e:
            print(f"日期解析错误: {date_str}, {e}")
            return None
    
    def parse_blacklist_line(self, line):
        """
        解析黑名单数据行
        格式: IP地址 # 日期(Y-M-D), 主机名, 国家代码, 黑名单类型ID
        例如: 185.26.173.9 # 2025-10-19, 185.26.173.9, SRB, 1
        """
        # 跳过注释行和空行
        if line.startswith('#') or not line.strip():
            return None
            
        # 使用正则表达式解析数据
        pattern = r'^(\S+)\s*#\s*(\d{4}-\d{2}-\d{2}),\s*([^,]*),\s*([^,]*),\s*(\d+)'
        match = re.match(pattern, line.strip())
        
        if match:
            ip = match.group(1).strip()
            date_str = match.group(2).strip()
            hostname = match.group(3).strip()
            country_id = match.group(4).strip()
            blacklist_type = int(match.group(5).strip()) + 1000
            
            # 转换日期为时间戳
            publish_date = self.parse_date_to_timestamp(date_str)
            if publish_date is None:
                return None
            
            return {
                "ip": ip,
                "publishDate": publish_date,
                # 使用解析到的主机名作为url；如果为空则回退到base_url
                "url": hostname if hostname else ip,
                "countryID": country_id,
                "blacklistType": blacklist_type
            }
        else:
            # 如果正则匹配失败，尝试简单解析
            if '#' in line:
                parts = line.split('#', 1)
                if len(parts) == 2:
                    ip = parts[0].strip()
                    comment_parts = parts[1].strip().split(',')
                    if len(comment_parts) >= 4:
                        date_str = comment_parts[0].strip()
                        hostname = comment_parts[1].strip() if len(comment_parts) > 1 else ""
                        country_id = comment_parts[2].strip()
                        try:
                            blacklist_type = int(comment_parts[3].strip()) + 1000
                            publish_date = self.parse_date_to_timestamp(date_str)
                            if publish_date is not None:
                                return {
                                    "ip": ip,
                                    "publishDate": publish_date,
                                    # 使用解析到的主机名作为url；如果为空则回退到base_url
                                    "url": hostname if hostname else ip,
                                    "countryID": country_id,
                                    "blacklistType": blacklist_type
                                }
                        except (ValueError, IndexError):
                            pass
            return None
    
    def process_data(self, raw_data):
        """
        处理原始数据，转换为JSON格式，对于重复IP用新数据更新已有数据
        """
        if not raw_data:
            return []
        
        lines = raw_data.split('\n')
        new_data_count = 0
        updated_data_count = 0
        
        print(f"开始处理 {len(lines)} 行数据...")
        
        for i, line in enumerate(lines):
            if i % 100 == 0 and i > 0:
                print(f"已处理 {i} 行...")
                
            parsed_item = self.parse_blacklist_line(line)
            if parsed_item:
                ip_address = parsed_item['ip']
                
                if ip_address in self.existing_data:
                    # IP已存在，用新数据更新
                    self.existing_data[ip_address] = parsed_item
                    updated_data_count += 1
                else:
                    # 新IP，添加到数据中
                    self.existing_data[ip_address] = parsed_item
                    new_data_count += 1
        
        # 返回所有数据（包括更新的和新增的）
        all_data = list(self.existing_data.values())
        
        print(f"处理完成，共解析出 {new_data_count + updated_data_count} 条有效数据")
        print(f"其中新增数据: {new_data_count} 条")
        print(f"更新数据: {updated_data_count} 条")
        print(f"总数据量: {len(all_data)} 条")
        
        return all_data, new_data_count, updated_data_count
    
    def save_to_json(self, data, new_count, updated_count):
        """
        保存所有数据到JSON文件，重写整个数据文件
        """
        if not data:
            print("没有数据需要保存")
            return True
        
        try:
            # 重写整个数据文件
            with open(self.existing_data_file, 'w', encoding='utf-8') as f:
                for item in data:
                    json_line = json.dumps(item, ensure_ascii=False, separators=(',', ':'))
                    f.write(json_line + '\n')
            
            print(f"数据已保存到 {self.existing_data_file}")
            print(f"总数据量: {len(data)} 条")
            print(f"其中新增: {new_count} 条，更新: {updated_count} 条")
            
            return True
        except Exception as e:
            print(f"保存文件失败: {e}")
            return False
    

    def run(self):
        """
        运行完整的数据处理流程，支持数据更新
        """
        print("开始威胁URL数据处理...")
        
        # 加载已有数据
        self.load_existing_data()
        
        # 获取原始数据
        raw_data = self.fetch_blacklist_data()
        if not raw_data:
            print("无法获取数据，程序退出")
            return False
        
        # 处理数据（包含更新逻辑）
        processed_data, new_count, updated_count = self.process_data(raw_data)
        
        # 保存所有数据
        success = self.save_to_json(processed_data, new_count, updated_count)
        
        if success:
            if new_count > 0 or updated_count > 0:
                print("威胁URL数据处理完成！")
                # 显示示例数据
                if new_count > 0:
                    print(f"\n新增数据示例 (共{new_count}条):")
                    # 显示前3条数据作为示例
                    for i, item in enumerate(processed_data[:3]):
                        print(f"{i+1}. {json.dumps(item, ensure_ascii=False)}")
                
                if updated_count > 0:
                    print(f"\n已更新 {updated_count} 条现有数据")
            else:
                print("没有新增或更新的数据")
        else:
            print("数据保存失败")
        
        return success


def main():
    """
    主函数
    """
    processor = ThreatURLProcessor()
    processor.run()


if __name__ == "__main__":
    main()