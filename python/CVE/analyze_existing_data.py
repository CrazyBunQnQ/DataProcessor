#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分析现有CVE.json文件的脚本
用于了解数据结构、统计CVE和CNNVD编码数量
"""

import json
import os
from typing import Set, Dict, Any


def analyze_existing_cve_data(file_path: str) -> Dict[str, Any]:
    """
    分析现有CVE数据文件
    
    Args:
        file_path: CVE.json文件路径
        
    Returns:
        分析结果字典
    """
    if not os.path.exists(file_path):
        print(f"文件不存在: {file_path}")
        return {}
    
    print(f"正在分析文件: {file_path}")
    print(f"文件大小: {os.path.getsize(file_path) / (1024*1024):.2f} MB")
    
    cve_ids = set()
    cnnvd_ids = set()
    total_records = 0
    max_id = 0
    sample_record = None
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # 尝试逐行读取以处理大文件
            content = f.read()
            
        # 解析JSON
        data = json.loads(content)
        
        if isinstance(data, list):
            total_records = len(data)
            print(f"总记录数: {total_records}")
            
            # 分析前几条记录的结构
            if data:
                sample_record = data[0]
                print("\n示例记录结构:")
                for key, value in sample_record.items():
                    print(f"  {key}: {type(value).__name__} = {str(value)[:100]}")
            
            # 统计CVE和CNNVD编码
            for i, record in enumerate(data):
                if i % 10000 == 0:
                    print(f"处理进度: {i}/{total_records}")
                
                # 提取CVE ID
                cve_id = record.get('cve') or record.get('nvdCve')
                if cve_id:
                    cve_ids.add(cve_id)
                
                # 提取CNNVD ID
                cnnvd_id = record.get('cnnvd')
                if cnnvd_id:
                    cnnvd_ids.add(cnnvd_id)
                
                # 提取最大ID
                record_id = record.get('id')
                if record_id:
                    try:
                        id_num = int(record_id)
                        max_id = max(max_id, id_num)
                    except (ValueError, TypeError):
                        pass
        
        else:
            print("数据格式不是列表")
            return {}
    
    except json.JSONDecodeError as e:
        print(f"JSON解析错误: {e}")
        return {}
    except Exception as e:
        print(f"处理文件时出错: {e}")
        return {}
    
    result = {
        'total_records': total_records,
        'unique_cve_count': len(cve_ids),
        'unique_cnnvd_count': len(cnnvd_ids),
        'max_id': max_id,
        'cve_ids': cve_ids,
        'cnnvd_ids': cnnvd_ids,
        'sample_record': sample_record
    }
    
    print(f"\n分析结果:")
    print(f"总记录数: {total_records}")
    print(f"唯一CVE数量: {len(cve_ids)}")
    print(f"唯一CNNVD数量: {len(cnnvd_ids)}")
    print(f"最大ID: {max_id}")
    
    return result


def main():
    """主函数"""
    file_path = r"D:\Downloads\CVE.json"
    
    print("开始分析现有CVE数据...")
    result = analyze_existing_cve_data(file_path)
    
    if result:
        # 保存分析结果
        output_file = "existing_data_analysis.json"
        # 不保存完整的ID集合，只保存统计信息
        summary = {
            'total_records': result['total_records'],
            'unique_cve_count': result['unique_cve_count'],
            'unique_cnnvd_count': result['unique_cnnvd_count'],
            'max_id': result['max_id'],
            'sample_record': result['sample_record']
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)
        
        print(f"\n分析结果已保存到: {output_file}")


if __name__ == "__main__":
    main()