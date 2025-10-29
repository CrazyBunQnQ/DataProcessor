#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Base64加密解密处理器
根据文件第一行判断格式：
- 如果是JSON格式：对每行进行base64加密
- 如果不是JSON格式：对每行进行base64解密
"""

import argparse
import base64
import json
import os
import sys
from pathlib import Path


class Base64Processor:
    def __init__(self, input_file):
        self.input_file = Path(input_file)
        self.output_file = None
        
    def is_json_line(self, line):
        """
        判断一行文本是否为有效的JSON格式
        """
        try:
            line = line.strip()
            if not line:
                return False
            json.loads(line)
            return True
        except (json.JSONDecodeError, ValueError):
            return False
    
    def detect_file_format(self):
        """
        检测文件格式，读取第一行判断是否为JSON
        """
        try:
            with open(self.input_file, 'r', encoding='utf-8') as f:
                first_line = f.readline().strip()
                if not first_line:
                    print("文件为空或第一行为空")
                    return None
                
                is_json = self.is_json_line(first_line)
                print(f"检测到文件格式: {'JSON' if is_json else '非JSON'}")
                return is_json
        except FileNotFoundError:
            print(f"错误: 文件 '{self.input_file}' 不存在")
            return None
        except Exception as e:
            print(f"读取文件时发生错误: {e}")
            return None
    
    def encode_to_base64(self, text):
        """
        将文本编码为base64
        """
        try:
            # 将字符串转换为字节，然后编码为base64
            text_bytes = text.encode('utf-8')
            base64_bytes = base64.b64encode(text_bytes)
            return base64_bytes.decode('utf-8')
        except Exception as e:
            print(f"Base64编码错误: {e}")
            return None
    
    def decode_from_base64(self, base64_text):
        """
        将base64文本解码为原始文本
        """
        try:
            # 解码base64为字节，然后转换为字符串
            base64_bytes = base64_text.encode('utf-8')
            text_bytes = base64.b64decode(base64_bytes)
            return text_bytes.decode('utf-8')
        except Exception as e:
            print(f"Base64解码错误: {e}")
            return None
    
    def process_json_to_base64(self):
        """
        处理JSON文件：每行进行base64加密
        """
        # 生成输出文件名
        self.output_file = self.input_file.with_suffix('.b64')
        
        try:
            with open(self.input_file, 'r', encoding='utf-8') as input_f, \
                 open(self.output_file, 'w', encoding='utf-8') as output_f:
                
                line_count = 0
                processed_count = 0
                
                print(f"开始处理JSON文件，进行base64加密...")
                
                for line in input_f:
                    line_count += 1
                    line = line.strip()
                    
                    if not line:
                        continue
                    
                    # 对每行进行base64编码
                    encoded_line = self.encode_to_base64(line)
                    if encoded_line:
                        output_f.write(encoded_line + '\n')
                        processed_count += 1
                    
                    if line_count % 100 == 0:
                        print(f"已处理 {line_count} 行...")
                
                print(f"处理完成！")
                print(f"总行数: {line_count}")
                print(f"成功加密: {processed_count} 行")
                print(f"输出文件: {self.output_file}")
                return True
                
        except Exception as e:
            print(f"处理JSON文件时发生错误: {e}")
            return False
    
    def process_base64_to_json(self):
        """
        处理base64文件：每行进行base64解密为JSON
        """
        # 生成输出文件名
        self.output_file = self.input_file.with_suffix('.json')
        
        try:
            with open(self.input_file, 'r', encoding='utf-8') as input_f, \
                 open(self.output_file, 'w', encoding='utf-8') as output_f:
                
                line_count = 0
                processed_count = 0
                
                print(f"开始处理base64文件，进行解密...")
                
                for line in input_f:
                    line_count += 1
                    line = line.strip()
                    
                    if not line:
                        continue
                    
                    # 对每行进行base64解码
                    decoded_line = self.decode_from_base64(line)
                    if decoded_line:
                        # 验证解码后的内容是否为有效JSON
                        if self.is_json_line(decoded_line):
                            output_f.write(decoded_line + '\n')
                            processed_count += 1
                        else:
                            print(f"警告: 第 {line_count} 行解码后不是有效的JSON格式")
                    
                    if line_count % 100 == 0:
                        print(f"已处理 {line_count} 行...")
                
                print(f"处理完成！")
                print(f"总行数: {line_count}")
                print(f"成功解密: {processed_count} 行")
                print(f"输出文件: {self.output_file}")
                return True
                
        except Exception as e:
            print(f"处理base64文件时发生错误: {e}")
            return False
    
    def process(self):
        """
        主处理函数
        """
        if not self.input_file.exists():
            print(f"错误: 输入文件 '{self.input_file}' 不存在")
            return False
        
        print(f"开始处理文件: {self.input_file}")
        
        # 检测文件格式
        is_json = self.detect_file_format()
        if is_json is None:
            return False
        
        # 根据格式选择处理方式
        if is_json:
            print("检测到JSON格式，将进行base64加密...")
            return self.process_json_to_base64()
        else:
            print("检测到非JSON格式，将进行base64解密...")
            return self.process_base64_to_json()


def main():
    """
    主函数，处理命令行参数
    """
    parser = argparse.ArgumentParser(
        description='Base64加密解密处理器',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python base64_processor.py input.json        # 对JSON文件进行base64加密
  python base64_processor.py input.b64         # 对base64文件进行解密为JSON
        """
    )
    
    parser.add_argument(
        'input_file',
        help='输入文件路径'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='显示详细信息'
    )
    
    args = parser.parse_args()
    
    # 创建处理器实例
    processor = Base64Processor(args.input_file)
    
    # 执行处理
    success = processor.process()
    
    if success:
        print("处理成功完成！")
        sys.exit(0)
    else:
        print("处理失败！")
        sys.exit(1)


if __name__ == "__main__":
    main()