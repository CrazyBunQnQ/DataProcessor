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
        处理原始数据，转换为JSON格式
        """
        if not raw_data:
            return []
        
        lines = raw_data.split('\n')
        processed_data = []
        
        print(f"开始处理 {len(lines)} 行数据...")
        
        for i, line in enumerate(lines):
            if i % 100 == 0 and i > 0:
                print(f"已处理 {i} 行...")
                
            parsed_item = self.parse_blacklist_line(line)
            if parsed_item:
                processed_data.append(parsed_item)
        
        print(f"处理完成，共解析出 {len(processed_data)} 条有效数据")
        return processed_data
    
    def save_to_json(self, data):
        """
        保存数据到JSON文件，每行一条独立的JSON数据
        """
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                for item in data:
                    json_line = json.dumps(item, ensure_ascii=False, separators=(',', ':'))
                    f.write(json_line + '\n')
            
            print(f"数据已保存到 {self.output_file}")
            print(f"共保存 {len(data)} 条记录")
            return True
        except Exception as e:
            print(f"保存文件失败: {e}")
            return False
    
    def run(self):
        """
        运行完整的数据处理流程
        """
        print("开始威胁URL数据处理...")
        
        # 获取原始数据
        raw_data = self.fetch_blacklist_data()
        if not raw_data:
            print("无法获取数据，程序退出")
            return False
        
        # 处理数据
        processed_data = self.process_data(raw_data)
        if not processed_data:
            print("没有有效数据可处理")
            return False
        
        # 保存数据
        success = self.save_to_json(processed_data)
        
        if success:
            print("威胁URL数据处理完成！")
            # 显示示例数据
            print("\n示例数据:")
            for i, item in enumerate(processed_data[:3]):
                print(f"{i+1}. {json.dumps(item, ensure_ascii=False)}")
        
        return success


def main():
    """
    主函数
    """
    processor = ThreatURLProcessor()
    processor.run()


if __name__ == "__main__":
    main()