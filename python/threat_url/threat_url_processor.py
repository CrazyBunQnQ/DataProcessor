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

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ThreatURLProcessor:
    def __init__(self):
        self.source_url = "https://myip.ms/files/blacklist/general/latest_blacklist.txt"
        self.base_url = "https://myip.ms/browse/blacklist"
        # 生成带日期的输出文件名
        current_date = datetime.now().strftime("%Y%m%d")
        self.output_file = f"threat_urls_incremental_{current_date}.json"
        self.existing_data_file = "threat_urls.json"
        self.existing_ips = set()  # 存储已有的IP地址
        
    def fetch_blacklist_data(self):
        """
        从源URL获取黑名单数据
        """
        try:
            print(f"正在从 {self.source_url} 获取数据...")
            # 添加SSL验证跳过和用户代理
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(self.source_url, timeout=30, verify=False, headers=headers)
            response.raise_for_status()
            print("数据获取成功")
            return response.text
        except requests.RequestException as e:
            print(f"获取数据失败: {e}")
            return None
    
    def load_existing_data(self):
        """
        读取已有的威胁URL数据文件，提取IP地址用于去重
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
                                self.existing_ips.add(data['ip'])
                        except json.JSONDecodeError as e:
                            print(f"解析第 {line_num} 行JSON数据失败: {e}")
                            continue
            
            print(f"已加载 {len(self.existing_ips)} 个已有IP地址用于去重")
            
        except Exception as e:
            print(f"读取已有数据文件失败: {e}")
            self.existing_ips = set()  # 重置为空集合
    
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
            blacklist_type = int(match.group(5).strip())
            
            # 转换日期为时间戳
            publish_date = self.parse_date_to_timestamp(date_str)
            if publish_date is None:
                return None
            
            return {
                "ip": ip,
                "publishDate": publish_date,
                "url": self.base_url,
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
                        country_id = comment_parts[2].strip()
                        try:
                            blacklist_type = int(comment_parts[3].strip())
                            publish_date = self.parse_date_to_timestamp(date_str)
                            if publish_date is not None:
                                return {
                                    "ip": ip,
                                    "publishDate": publish_date,
                                    "url": self.base_url,
                                    "countryID": country_id,
                                    "blacklistType": blacklist_type
                                }
                        except (ValueError, IndexError):
                            pass
            return None
    
    def process_data(self, raw_data):
        """
        处理原始数据，转换为JSON格式，并过滤已存在的IP地址
        """
        if not raw_data:
            return []
        
        lines = raw_data.split('\n')
        processed_data = []
        duplicate_count = 0
        
        print(f"开始处理 {len(lines)} 行数据...")
        
        for i, line in enumerate(lines):
            if i % 100 == 0 and i > 0:
                print(f"已处理 {i} 行...")
                
            parsed_item = self.parse_blacklist_line(line)
            if parsed_item:
                # 检查IP是否已存在
                ip_address = parsed_item['ip']
                if ip_address in self.existing_ips:
                    duplicate_count += 1
                    continue  # 跳过已存在的IP
                else:
                    # 添加到已存在IP集合中，避免本次处理中的重复
                    self.existing_ips.add(ip_address)
                    processed_data.append(parsed_item)
        
        print(f"处理完成，共解析出 {len(processed_data) + duplicate_count} 条有效数据")
        print(f"其中新增数据: {len(processed_data)} 条")
        print(f"重复数据(已跳过): {duplicate_count} 条")
        return processed_data
    
    def save_to_json(self, data):
        """
        保存增量数据到JSON文件，每行一条独立的JSON数据
        """
        if not data:
            print("没有新增数据需要保存")
            return True
        
        try:
            # 保存增量数据到单独文件
            with open(self.output_file, 'w', encoding='utf-8') as f:
                for item in data:
                    json_line = json.dumps(item, ensure_ascii=False, separators=(',', ':'))
                    f.write(json_line + '\n')
            
            print(f"增量数据已保存到 {self.output_file}")
            print(f"共保存 {len(data)} 条新增记录")
            
            # 将新增数据追加到原有数据文件
            self.append_to_existing_data(data)
            
            return True
        except Exception as e:
            print(f"保存文件失败: {e}")
            return False
    
    def append_to_existing_data(self, data):
        """
        将新增数据追加到原有数据文件中
        """
        try:
            with open(self.existing_data_file, 'a', encoding='utf-8') as f:
                for item in data:
                    json_line = json.dumps(item, ensure_ascii=False, separators=(',', ':'))
                    f.write(json_line + '\n')
            
            print(f"新增数据已追加到 {self.existing_data_file}")
        except Exception as e:
            print(f"追加数据到原有文件失败: {e}")
    
    def run(self):
        """
        运行完整的增量数据处理流程
        """
        print("开始威胁URL增量数据处理...")
        
        # 加载已有数据用于去重
        self.load_existing_data()
        
        # 获取原始数据
        raw_data = self.fetch_blacklist_data()
        if not raw_data:
            print("无法获取数据，程序退出")
            return False
        
        # 处理数据（包含去重逻辑）
        processed_data = self.process_data(raw_data)
        
        # 保存增量数据
        success = self.save_to_json(processed_data)
        
        if success:
            if processed_data:
                print("威胁URL增量数据处理完成！")
                # 显示示例数据
                print("\n新增数据示例:")
                for i, item in enumerate(processed_data[:3]):
                    print(f"{i+1}. {json.dumps(item, ensure_ascii=False)}")
            else:
                print("威胁URL数据处理完成！本次没有新增数据。")
        
        return success


def main():
    """
    主函数
    """
    processor = ThreatURLProcessor()
    processor.run()


if __name__ == "__main__":
    main()