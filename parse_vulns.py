#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
解析Maven漏洞数据文件的脚本
提取GHSA编号、CVE编号、github_reviewed以及affected包信息
并将结果保存为CSV格式
"""

import os
import json
import csv
import re
from pathlib import Path
from datetime import datetime
def extract_cve(aliases):
    """从aliases列表中提取CVE编号"""
    if not aliases:
        return ""
    
    for alias in aliases:
        if alias.startswith("CVE-"):
            return alias
    
    return ""

def flatten_ranges(ranges):
    """处理并提取ranges中的introduced和fixed版本信息"""
    introduced = []
    fixed = []
    
    if not ranges:
        return "", ""
    
    for range_item in ranges:
        if range_item.get("type") == "ECOSYSTEM":
            events = range_item.get("events", [])
            for event in events:
                if "introduced" in event:
                    introduced.append(str(event["introduced"]))
                if "fixed" in event:
                    fixed.append(str(event["fixed"]))
    
    return ",".join(introduced), ",".join(fixed)

def extract_versions(versions):
    """处理versions列表"""
    if not versions:
        return ""
    
    return ",".join(str(v) for v in versions)

def parse_vuln_file(file_path):
    """解析单个漏洞文件并返回记录列表"""
    records = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 提取GHSA编号
        vul_id = data.get("id", "")
        
        # 如果文件名中包含GHSA编号但JSON中没有，则从文件名提取
        
        
        # 提取CVE编号
        cve_id = extract_cve(data.get("aliases", []))
        
        # 提取github_reviewed状态
        github_reviewed = data.get("database_specific", {}).get("github_reviewed", False)
        
        # 处理affected列表
        affected_list = data.get("affected", [])
        if not affected_list:
            # 如果没有affected信息，仍然创建一条基本记录
            records.append({
                "vul_id": vul_id,
                "cve_id": cve_id,
                "github_reviewed": github_reviewed,
                "name": "",
                "ecosystem": "",
                "purl": "",
                "ranges_introduced": "",
                "ranges_fixed": "", 
                "versions": ""
            })
        else:
            for affected in affected_list:
                package = affected.get("package", {})
                name = package.get("name", "")
                ecosystem = package.get("ecosystem", "")
                purl = package.get("purl", "")
                
                ranges_introduced, ranges_fixed = flatten_ranges(affected.get("ranges", []))
                versions = extract_versions(affected.get("versions", []))
                
                records.append({
                    "vul_id": vul_id,
                    "cve_id": cve_id,
                    "github_reviewed": github_reviewed,
                    "name": name,
                    "ecosystem": ecosystem,
                    "purl": purl,
                    "ranges_introduced": ranges_introduced,
                    "ranges_fixed": ranges_fixed,
                    "versions": versions
                })
    
    except Exception as e:
        print(f"处理文件 {file_path} 时出错: {str(e)}")
        # 出错时返回一条错误记录
        raise e
    
    return records

def parse_specific_ecosystem(ecosystem):
    """主函数"""
    # 源目录和输出文件
    date = datetime.now().strftime("%Y%m%d")
    input_dir = os.path.join(os.getcwd(), "data", ecosystem)
    output_dir = os.path.join(os.getcwd(), "data_parsed", ecosystem)
    os.makedirs(output_dir, exist_ok=True)
    output_file_with_cve = Path(output_dir, f"maven_vulnerabilities_with_cve_{date}.csv")
    output_file_without_cve = Path(output_dir, f"maven_vulnerabilities_without_cve_{date}.csv")
        
    # 字段名
    fieldnames = [
        "vul_id", "cve_id", "github_reviewed", 
        "name", "ecosystem", "purl", 
        "ranges_introduced", "ranges_fixed", "versions"
    ]
    
    # 分别存储有CVE和无CVE的记录
    records_with_cve = []
    records_without_cve = []
    
    # 处理目录中的所有JSON文件
    json_files = [os.path.join(input_dir, f) for f in os.listdir(input_dir) if f.endswith('.json')]
    print(f"发现 {len(json_files)} 个JSON文件")
    
    for file_path in json_files:
        try:
            records = parse_vuln_file(file_path)
        except Exception as e:
            print(f"处理文件 {file_path} 时出错: {str(e)}")
            continue
        for record in records:
            purl = record["purl"]
            if not purl.startswith(f"pkg:{ecosystem.lower()}"):
                print(f"文件 {file_path} 的purl {purl} 不属于 {ecosystem} 生态系统")
                continue
            if record["cve_id"]:  # 如果有CVE编号
                records_with_cve.append(record)
            else:  # 如果没有CVE编号
                records_without_cve.append(record)
    
    # 写入有CVE的记录到CSV文件
    with open(output_file_with_cve, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records_with_cve)
    
    # 写入无CVE的记录到CSV文件
    with open(output_file_without_cve, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records_without_cve)
    
    print(f"处理完成，共生成 {len(records_with_cve) + len(records_without_cve)} 条记录")
    print(f"有CVE编号的记录: {len(records_with_cve)} 条，已保存到: {output_file_with_cve}")
    print(f"无CVE编号的记录: {len(records_without_cve)} 条，已保存到: {output_file_without_cve}")

if __name__ == "__main__":
    parse_specific_ecosystem("Maven") 