#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE数据处理脚本
将XML格式的漏洞数据转换为JSON格式，并实现增量更新功能
支持基于现有数据的去重和ID递增
"""

import os
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional, Set
import re


class CVEProcessor:
    """CVE数据处理器"""
    
    def __init__(self, data_dir: str = "data", existing_data_file: str = None):
        """
        初始化CVE处理器
        
        Args:
            data_dir: 数据目录路径
            existing_data_file: 现有CVE数据文件路径
        """
        self.data_dir = data_dir
        self.existing_data_file = existing_data_file
        self.cve_data = {}  # 用于存储去重后的CVE数据，key为CVE ID
        self.existing_cve_ids = set()  # 现有CVE ID集合
        self.existing_cnnvd_ids = set()  # 现有CNNVD ID集合
        self.next_id = 1  # 下一个可用的ID
        self.existing_data_count = 0  # 现有数据数量
        
        # 如果指定了现有数据文件，则加载现有数据
        if self.existing_data_file:
            self.load_existing_data()
    
    def load_existing_data(self) -> None:
        """
        加载现有CVE数据文件，提取CVE和CNNVD ID用于去重
        采用内存优化的方式处理大文件
        """
        if not self.existing_data_file or not os.path.exists(self.existing_data_file):
            print(f"现有数据文件不存在: {self.existing_data_file}")
            return
        
        print(f"正在加载现有数据: {self.existing_data_file}")
        file_size = os.path.getsize(self.existing_data_file) / (1024*1024)
        print(f"文件大小: {file_size:.2f} MB")
        
        try:
            with open(self.existing_data_file, 'r', encoding='utf-8') as f:
                # 对于大文件，使用流式解析
                content = f.read()
                data = json.loads(content)
                
                if isinstance(data, list):
                    self.existing_data_count = len(data)
                    print(f"现有数据记录数: {self.existing_data_count}")
                    
                    # 提取CVE和CNNVD ID
                    for i, record in enumerate(data):
                        if i % 20000 == 0:
                            print(f"加载进度: {i}/{self.existing_data_count}")
                        
                        # 提取CVE ID
                        cve_id = record.get('cve') or record.get('nvdCve')
                        if cve_id:
                            self.existing_cve_ids.add(cve_id)
                        
                        # 提取CNNVD ID
                        cnnvd_id = record.get('cnnvd')
                        if cnnvd_id:
                            self.existing_cnnvd_ids.add(cnnvd_id)
                        
                        # 更新下一个可用ID
                        record_id = record.get('id')
                        if record_id:
                            try:
                                id_num = int(record_id)
                                self.next_id = max(self.next_id, id_num + 1)
                            except (ValueError, TypeError):
                                pass
                    
                    print(f"加载完成:")
                    print(f"  现有CVE数量: {len(self.existing_cve_ids)}")
                    print(f"  现有CNNVD数量: {len(self.existing_cnnvd_ids)}")
                    print(f"  下一个可用ID: {self.next_id}")
                    
        except Exception as e:
            print(f"加载现有数据时出错: {e}")
            # 如果加载失败，从1开始
            self.next_id = 1
    
    def parse_xml_file(self, xml_file: str) -> List[Dict]:
        """
        解析单个XML文件
        
        Args:
            xml_file: XML文件路径
            
        Returns:
            解析后的CVE数据列表
        """
        cve_list = []
        
        # 提取文件名中的月份信息用于排序
        filename = os.path.basename(xml_file)
        month_info = self._extract_month_from_filename(filename)
        
        try:
            # 先读取文件内容并进行预处理
            with open(xml_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 修复常见的XML格式问题
            content = self._fix_xml_content(content)
            
            # 解析修复后的XML内容
            root = ET.fromstring(content)
            
            for entry in root.findall('entry'):
                cve_data = self._parse_entry(entry, month_info)
                if cve_data:
                    cve_list.append(cve_data)
                    
        except ET.ParseError as e:
            print(f"解析XML文件 {xml_file} 时出错: {e}")
            # 尝试逐个entry解析
            cve_list = self._parse_xml_by_entries(xml_file, month_info)
        except Exception as e:
            print(f"处理文件 {xml_file} 时出错: {e}")
            
        return cve_list
    
    def _fix_xml_content(self, content: str) -> str:
        """
        修复XML内容中的格式问题
        
        Args:
            content: 原始XML内容
            
        Returns:
            修复后的XML内容
        """
        import re
        
        # 1. 修复文本内容中的&符号（不处理已经正确转义的）
        def fix_ampersand(match):
            text = match.group(0)
            # 只替换没有正确转义的&符号
            text = re.sub(r'&(?!amp;|lt;|gt;|quot;|apos;)', '&amp;', text)
            return text
        
        # 处理标签之间的文本内容中的&符号
        content = re.sub(r'>[^<]*<', fix_ampersand, content)
        
        # 2. 修复描述文本中的<filename>等伪标签
        # 将描述文本中的<filename>转义为&lt;filename&gt;
        def fix_pseudo_tags(text):
            # 转义常见的伪标签
            pseudo_tags = ['filename', 'path', 'url', 'script', 'style', 'div', 'span', 'img', 'a']
            for tag in pseudo_tags:
                # 转义开始标签
                text = re.sub(f'<{tag}>', f'&lt;{tag}&gt;', text, flags=re.IGNORECASE)
                # 转义结束标签
                text = re.sub(f'</{tag}>', f'&lt;/{tag}&gt;', text, flags=re.IGNORECASE)
                # 转义自闭合标签
                text = re.sub(f'<{tag}/>', f'&lt;{tag}/&gt;', text, flags=re.IGNORECASE)
            return text
        
        # 只在vuln-descript标签内容中处理伪标签
        content = re.sub(r'<vuln-descript>(.*?)</vuln-descript>', 
                        lambda m: f'<vuln-descript>{fix_pseudo_tags(m.group(1))}</vuln-descript>', 
                        content, flags=re.DOTALL)
        
        return content
    
    def _parse_xml_by_entries(self, xml_file: str, month_info: str) -> List[Dict]:
        """
        逐个entry解析XML文件（当整体解析失败时使用）
        
        Args:
            xml_file: XML文件路径
            month_info: 月份信息
            
        Returns:
            解析后的CVE数据列表
        """
        cve_list = []
        
        try:
            with open(xml_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 使用正则表达式提取每个entry
            import re
            entry_pattern = r'<entry>(.*?)</entry>'
            entries = re.findall(entry_pattern, content, re.DOTALL)
            
            print(f"  通过正则表达式找到 {len(entries)} 个entry")
            
            for i, entry_content in enumerate(entries):
                try:
                    # 构建完整的entry XML
                    entry_xml = f"<entry>{entry_content}</entry>"
                    entry_xml = self._fix_xml_content(entry_xml)
                    
                    # 解析单个entry
                    entry_root = ET.fromstring(entry_xml)
                    cve_data = self._parse_entry(entry_root, month_info)
                    if cve_data:
                        cve_list.append(cve_data)
                        
                except Exception as e:
                    print(f"    跳过第 {i+1} 个entry，解析错误: {e}")
                    continue
                    
        except Exception as e:
            print(f"逐个entry解析失败: {e}")
            
        return cve_list
    
    def _extract_month_from_filename(self, filename: str) -> str:
        """
        从文件名中提取月份信息
        
        Args:
            filename: 文件名
            
        Returns:
            月份信息字符串
        """
        if filename.startswith("当月"):
            return "当月"
        elif filename.startswith("9月"):
            return "9月"
        elif filename.startswith("8月"):
            return "8月"
        else:
            # 尝试从文件名中提取月份
            month_match = re.search(r'(\d+月)', filename)
            if month_match:
                return month_match.group(1)
            return "未知"
    
    def _parse_entry(self, entry: ET.Element, month_info: str) -> Optional[Dict]:
        """
        解析单个entry元素
        
        Args:
            entry: XML entry元素
            month_info: 月份信息
            
        Returns:
            解析后的CVE数据字典
        """
        try:
            # 提取CVE ID
            cve_id_elem = entry.find('.//cve-id')
            cve_id = cve_id_elem.text if cve_id_elem is not None else None
            
            if not cve_id:
                return None
            
            # 构建CVE数据对象，映射到Java实体字段
            cve_data = {
                # 基础信息
                "nvdCve": cve_id,  # 对应nvdCve字段
                "cve": cve_id,     # 对应cve字段
                "cnnvd": self._get_text(entry, 'vuln-id'),  # CNNVD编号
                
                # 描述信息
                "vulnDescription": self._get_text(entry, 'vuln-descript'),  # 漏洞描述
                "description": self._get_text(entry, 'vuln-descript'),      # 详述
                "title": self._get_text(entry, 'name'),                     # 标题
                "enTitle": None,  # 英文标题，XML中没有对应字段
                
                # 时间信息
                "publishDate": self._get_text(entry, 'published'),  # 发布日期
                "pubDate": self._get_text(entry, 'published'),      # 出版日期
                
                # 威胁信息
                "cnnvdThreatType": self._get_text(entry, 'vuln-type'),  # 威胁类型
                "cnnvdType": self._get_text(entry, 'vuln-type'),        # 漏洞类型
                "level": self._map_severity(self._get_text(entry, 'severity')),  # 漏洞级别
                "severity": self._map_severity_to_int(self._get_text(entry, 'severity')),  # 严重程度数值
                
                # 解决方案
                "solution": self._get_text(entry, 'vuln-solution'),  # 处理建议
                
                # 其他字段设为None或空值（XML中没有对应数据）
                "cpe": None,
                "cvssScoreTwice": None,
                "cvssVectorTwice": None,
                "cvssScoreThird": None,
                "cvssVectorThird": None,
                "cwe": None,
                "cweName": None,
                "references": None,
                "cnnvdUrl": None,
                "threatName": None,
                "reference": None,
                "category": None,
                "threatNameEng": None,
                "descriptionEng": None,
                "requirement": None,
                "caused": None,
                "valid": None,
                "defaultAction": None,
                "sid": None,
                "deleted": None,
                
                # 添加内部字段用于去重判断
                "_month_info": month_info,
                "_modified": self._get_text(entry, 'modified')
            }
            
            return cve_data
            
        except Exception as e:
            print(f"解析entry时出错: {e}")
            return None
    
    def _get_text(self, element: ET.Element, tag: str) -> Optional[str]:
        """
        安全获取XML元素的文本内容
        
        Args:
            element: XML元素
            tag: 标签名
            
        Returns:
            文本内容或None
        """
        child = element.find(tag)
        return child.text.strip() if child is not None and child.text else None
    
    def _map_severity(self, severity: str) -> Optional[str]:
        """
        映射严重程度文本
        
        Args:
            severity: 原始严重程度
            
        Returns:
            映射后的严重程度
        """
        if not severity:
            return None
        
        severity_map = {
            "超危": "CRITICAL",
            "高危": "HIGH", 
            "中危": "MEDIUM",
            "低危": "LOW"
        }
        
        return severity_map.get(severity, severity)
    
    def _map_severity_to_int(self, severity: str) -> Optional[int]:
        """
        映射严重程度为数值
        
        Args:
            severity: 原始严重程度
            
        Returns:
            严重程度数值
        """
        if not severity:
            return None
            
        severity_map = {
            "超危": 4,
            "高危": 3,
            "中危": 2,
            "低危": 1
        }
        
        return severity_map.get(severity, 0)
    
    def process_all_files(self) -> List[Dict]:
        """
        处理所有XML文件并合并去重
        支持增量更新，跳过现有数据中已存在的CVE
        
        Returns:
            合并去重后的CVE数据列表
        """
        xml_files = []
        
        # 获取所有XML文件
        for filename in os.listdir(self.data_dir):
            if filename.endswith('.xml'):
                xml_files.append(os.path.join(self.data_dir, filename))
        
        # 按文件名排序，确保当月文件最后处理（优先级最高）
        xml_files.sort(key=lambda x: (
            0 if "当月" in os.path.basename(x) else 
            1 if "9月" in os.path.basename(x) else 
            2 if "8月" in os.path.basename(x) else 3
        ), reverse=True)
        
        print(f"找到 {len(xml_files)} 个XML文件:")
        for file in xml_files:
            print(f"  - {os.path.basename(file)}")
        
        new_records_count = 0
        skipped_records_count = 0
        
        # 处理每个文件
        for xml_file in xml_files:
            print(f"\n正在处理: {os.path.basename(xml_file)}")
            cve_list = self.parse_xml_file(xml_file)
            
            file_new_count = 0
            file_skipped_count = 0
            
            # 合并数据，实现去重（以最新月份为准）
            for cve_data in cve_list:
                cve_id = cve_data.get('cve')
                if cve_id:
                    # 检查是否在现有数据中已存在
                    if cve_id in self.existing_cve_ids:
                        file_skipped_count += 1
                        continue
                    
                    if cve_id not in self.cve_data:
                        # 新的CVE，直接添加
                        self.cve_data[cve_id] = cve_data
                        file_new_count += 1
                    else:
                        # 已存在的CVE（在当前处理的数据中），比较月份优先级
                        existing = self.cve_data[cve_id]
                        if self._should_update(existing, cve_data):
                            self.cve_data[cve_id] = cve_data
            
            new_records_count += file_new_count
            skipped_records_count += file_skipped_count
            
            print(f"  处理了 {len(cve_list)} 条记录")
            print(f"  新增: {file_new_count} 条，跳过: {file_skipped_count} 条")
        
        print(f"\n处理汇总:")
        print(f"  总新增记录: {new_records_count}")
        print(f"  总跳过记录: {skipped_records_count}")
        
        # 清理内部字段并返回结果
        result = []
        current_id = self.next_id
        
        for cve_id, cve_data in self.cve_data.items():
            # 移除内部字段
            clean_data = {k: v for k, v in cve_data.items() if not k.startswith('_')}
            # 添加ID字段，从现有数据的最大ID继续递增
            clean_data['id'] = str(current_id)
            current_id += 1
            result.append(clean_data)
        
        return result
    
    def _should_update(self, existing: Dict, new: Dict) -> bool:
        """
        判断是否应该更新现有数据
        
        Args:
            existing: 现有数据
            new: 新数据
            
        Returns:
            是否应该更新
        """
        # 月份优先级：当月 > 9月 > 8月 > 其他
        priority_map = {
            "当月": 4,
            "9月": 3,
            "8月": 2
        }
        
        existing_priority = priority_map.get(existing.get('_month_info', ''), 1)
        new_priority = priority_map.get(new.get('_month_info', ''), 1)
        
        if new_priority > existing_priority:
            return True
        elif new_priority == existing_priority:
            # 同一月份，比较修改时间
            existing_modified = existing.get('_modified', '')
            new_modified = new.get('_modified', '')
            return new_modified > existing_modified
        
        return False
    
    def save_to_json(self, output_file: str, cve_data: List[Dict], is_incremental: bool = False) -> None:
        """
        保存数据到JSON文件，每个对象占一行
        
        Args:
            output_file: 输出文件路径
            cve_data: CVE数据列表
            is_incremental: 是否为增量更新模式
        """
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('[\n')  # 开始数组
                
                for i, item in enumerate(cve_data):
                    # 将每个对象序列化为一行JSON
                    json_line = json.dumps(item, ensure_ascii=False, separators=(',', ':'))
                    f.write(json_line)
                    
                    # 除了最后一个元素，都要添加逗号
                    if i < len(cve_data) - 1:
                        f.write(',')
                    
                    f.write('\n')  # 换行
                
                f.write(']')  # 结束数组
            
            if is_incremental:
                print(f"\n增量数据已保存到: {output_file}")
                print(f"新增了 {len(cve_data)} 条CVE记录")
                print(f"现有数据: {self.existing_data_count} 条")
                print(f"总数据量: {self.existing_data_count + len(cve_data)} 条")
            else:
                print(f"\n数据已保存到: {output_file}")
                print(f"总共处理了 {len(cve_data)} 条唯一CVE记录")
        except Exception as e:
            print(f"保存文件时出错: {e}")


def main():
    """主函数"""
    # 现有数据文件路径
    existing_data_file = r"D:\Downloads\CVE.json"
    
    # 创建处理器，指定现有数据文件
    processor = CVEProcessor(existing_data_file=existing_data_file)
    
    # 处理所有文件
    print("开始处理CVE数据（增量更新模式）...")
    cve_data = processor.process_all_files()
    
    # 生成输出文件名
    current_date = datetime.now().strftime("%Y%m%d")
    
    if len(cve_data) > 0:
        # 有新数据，生成增量文件
        output_file = f"CVE_incremental_{current_date}.json"
        is_incremental = True
    else:
        # 没有新数据
        output_file = f"CVE_no_new_data_{current_date}.json"
        is_incremental = False
    
    # 保存结果
    processor.save_to_json(output_file, cve_data, is_incremental)
    
    print(f"\n处理完成！")
    print(f"输出文件: {output_file}")
    
    if len(cve_data) > 0:
        print(f"\n增量更新说明:")
        print(f"- 现有数据文件: {existing_data_file}")
        print(f"- 现有数据量: {processor.existing_data_count} 条")
        print(f"- 新增数据量: {len(cve_data)} 条")
        print(f"- ID范围: {processor.next_id} - {processor.next_id + len(cve_data) - 1}")
    else:
        print(f"\n没有发现新的CVE数据，所有数据都已存在于现有文件中。")


if __name__ == "__main__":
    main()