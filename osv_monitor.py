#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OSV 漏洞数据库监控工具
用于同步 https://storage.googleapis.com/osv-vulnerabilities/index.html 的漏洞数据
"""

import os
import re
import time
import yaml
import logging
import requests
import schedule
import datetime
from pathlib import Path
from tqdm import tqdm
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
# 使用 playwright 代替 selenium
from playwright.sync_api import sync_playwright
import json
import csv
import pandas as pd
from datetime import datetime
import threading
import shutil

File_lock = threading.Lock()
FILE_DIR_NAME_TRANSFORM_RECORD = os.path.join(os.getcwd(), 'ECO_DIR_NAME_TRANSFORM_RECORD.csv')


# 配置日志
def setup_logging(logs_dir):
    """设置日志记录"""
    logs_dir = Path(logs_dir)
    logs_dir.mkdir(exist_ok=True, parents=True)
    
    log_file = logs_dir / f"osv_monitor_{datetime.now().strftime('%Y%m%d')}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger('osv_monitor')

# 加载配置
def load_config(config_path='config.yaml'):
    """从YAML文件加载配置"""
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

# 验证文件完整性
def check_validation(path):
    '''根据文件后缀打开文件看一下是否是文件是否发生损毁, 当前仅支持 json, csv, text'''
    file_path = Path(path) if type(path) is str else path
    try:
        if file_path.suffix.lower() == '.json':    
            with open(file_path, 'r') as f:
                json.load(f)  # 尝试解析JSON以验证完整性
        elif file_path.suffix.lower() in ['.csv','text']:
            with open(file_path, 'r') as f:
                reader = csv.reader(f)
    except Exception as e:
        logger.error(f"File {path} is invalid: {e}, retrying...")
        # 删除损毁文件
        if os.path.exists(file_path):
            os.remove(file_path)
        raise Exception("Invalid File")


# 下载文件
def download_file(url, dest_path, timeout=300, retries=3):
    """下载文件到指定路径，支持重试和进度条显示
    arg:
        - url: 文件下载 url
        - dest_path: 本地存储路径
        - timeout: 等待时长
        - 重试次数
    return: True|False 是否下载成功
    ps: 
      - 由于可能存在网络问题, 导致下载过程中失败, 或者下载到一半文件反而导致原始文件受损, 加入临时文件机制. 
      - 由于会多线程同时下载, 要确保下载文件目录(文件名)不会发生冲突
    """
    # 创建临时文件路径, 
    temp_file_path = dest_path.with_suffix('.tmp')
    if 'AlmaLinux:8/AlmaLinux:8' in str(dest_path):
        print('dd')
    # 我记得除了这种傻瓜式 for 循环处理, 应该有一个库可以简洁的设置 retry
    for attempt in range(retries):
        try:
            with requests.get(url, stream=True, timeout=timeout) as r:
                r.raise_for_status()
                dest_path.parent.mkdir(exist_ok=True, parents=True)
                
                # 下载到临时文件
                with open(temp_file_path, 'wb') as f:
                    # 如果想动态可视化, 可以这么写. 
                    # with tqdm(total=total_size, unit='B', unit_scale=True, desc=dest_path.name) as pbar:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            # pbar.update(len(chunk))
                
                # 验证文件完整性
                
                # 如果是 ecosystems.txt 文件, 则需要验证内容与本地文件是否发生改变
                if dest_path.name == 'ecosystems.txt':
                    with open(temp_file_path, 'r') as f:
                        reader = csv.reader(f)
                        remote_data = [row[0] for row in reader]
                        remote_data_set = set(remote_data)
                    with open(dest_path, 'r') as f:
                        reader = csv.reader(f)
                        local_data = [row[0] for row in reader]
                        local_data_set = set(local_data)
                    if remote_data_set != local_data_set:
                        logger.info(f"remote ecosystems.txt different with local, updating...")
                    else:
                        logger.info(f"remote ecosystems.txt same with local file, skiping...")
                        os.remove(temp_file_path)
                        return False
                # 下载成功，安全地替换目标文件
                if os.path.exists(dest_path):
                    # 创建备份，以防万一
                    backup_path = dest_path.with_suffix('.bak')
                    try:
                        if os.path.exists(backup_path):
                            os.remove(backup_path)
                        os.rename(dest_path, backup_path)
                    except Exception as e:
                        logger.warning(f"Creating backup file failed: {str(e)}")
                
                # 重命名临时文件为目标文件
                os.rename(temp_file_path, dest_path)
                
                # 删除备份文件（如果存在）
                backup_path = dest_path.with_suffix('.bak')
                if os.path.exists(backup_path):
                    try:
                        os.remove(backup_path)
                    except Exception as e:
                        logger.warning(f"Deleting backup file failed: {str(e)}")
                return True
        except Exception as e:
            logger.error(f"Dowloing {url} failed, retrying {attempt+1}/{retries}: {str(e)}")
            # 删除临时文件
            if os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                except Exception as e2:
                    logger.error(f'Deleting tmp file failed: {e2}, ignoring...')
                    pass
            # 下载失败的情况, 如果存在备份文件并且主文件不存在, 将备份恢复为主文件
            if attempt == retries - 1:
                # 恢复备份（如果存在）
                backup_path = dest_path.with_suffix('.bak')
                if os.path.exists(backup_path) and not os.path.exists(dest_path):
                    try:
                        os.rename(backup_path, dest_path)
                        logger.info(f"r {dest_path} 的备份")
                    except Exception as e:
                        logger.error(f"恢复备份文件失败: {str(e)}")
                # 删除完临时文件之后报错
                raise
            time.sleep(2 ** attempt)  # 指数退避
    return False

# 获取目录文件列表
def get_directory_files(base_url, ecosystem):
    """ 获取指定生态系统目录下的文件列表
    arg: 
        - base_url: osv 存储 url 前缀
        - ecosystem: 要下载的生态名
    """
    # 拼接 url, 本来其实还有一个 ordernumber, 但是这是个动态的, 放了会出问题, 不放反而没问题. 
    url = f"{base_url}index.html?prefix={ecosystem}/"
    
    try:
        def process_page(page):
            files = []
            
            # 获取所有文件元素（排除文件夹）
            file_elements = page.query_selector_all("td a:not([href*='?prefix='])")
            black_list = ['all.zip', 'ecosystems.txt', 'Parent Directory', f'{ecosystem}/all.zip']
            
            for elem in file_elements:
                file_name = elem.inner_text()
                if file_name not in black_list and file_name.strip() != '':
                    # 获取链接
                    href = elem.get_attribute('href')
                    
                    # 删除 generation 参数
                    if 'generation=' in href and '&alt=' in href:
                        href = href.replace(href[href.find('generation='):href.find('&alt=')], '')
                    
                    # 获取上级行的日期和大小信息
                    row_data = elem.evaluate("""el => {
                        const row = el.closest('tr');
                        const cells = row.querySelectorAll('td');
                        return {
                            date: cells[2].innerText,
                            size: cells[3].innerText
                        };
                    }""")
                    date_td = row_data['date']
                    size_td = row_data['size']
                    
                    files.append({
                        'name': file_name.replace(f'{ecosystem}/', ''),
                        'last_modified': date_td,
                        'size': size_td,
                        'full_url': href,
                        'ecosystem': transform_validate_dir(ecosystem)
                    })
            return files
        
        return with_playwright(url, process_page)
    except Exception as e:
        logger.error(f"获取目录 {ecosystem} 的文件列表失败: {str(e)}")
        return []

# def check_need_update(file_name, ecosystem_dir, remote_time=None):
#     """检查是否需要更新，返回(需要更新标志, 操作类型)"""
#     # 检查json文件是存在
#     local_file_path = ecosystem_dir / file_name
#     if not os.path.exists(local_file_path):
#         return True, "new_intro"
    
#     # 检查json文件是否有效
#     try:
#         with open(local_file_path, "r") as f:
#             data = json.load(f)
            
#         # 如果提供了远程修改时间，检查是否需要更新
#         if remote_time:
#             # 这里需要实现基于时间的比较逻辑
#             # 简化实现：如果远程时间不为空且与本地不同，则更新
#             return True, "update"
            
#         return False, ""
#     except Exception as e:
#         print(f"[-] Warning: 文件 {local_file_path} 损坏，删除")
#         os.remove(local_file_path)
#         return True, "new_intro"  # 文件损坏，需要重新下载

# ecosystem, local_rela_file, opcode, updated_records, sync_log_file
def log_file_operation(ecosystem, local_rela_file, operation_type, updated_records, sync_log_file):
    """记录文件操作到日志文件
    Args:
        ecosystem: 生态系统名称
        local_rela_file: 文件路径
        operation_type: 操作类型 (new_intro, updated, deleted)
        updated_records: 更新记录
        sync_log_file: 日志文件路径
    """
    if type(local_rela_file) != 'str':
        local_rela_file = str(local_rela_file)
    # 确保日志目录存在
    
    # 检查文件是否存在，不存在则创建并添加表头
    file_exists = os.path.isfile(sync_log_file)
    if operation_type == 'new_intro':
        with File_lock:
            with open(sync_log_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f, delimiter=',')
                # 如果文件不存在, 则创建并添加表头
                if not file_exists:
                    writer.writerow(['date', 'ecosystem', 'file_path', 'operation_type', 'last_update_time'])
                # 如果 operation_type 为 new_intro, 则新增记录
                writer.writerow(updated_records)
    # 更新或者删除, 或者更新记录
    if operation_type == 'updated' or operation_type == 'deleted':
        new_records = []
        with File_lock:
            with open(sync_log_file, 'r', encoding='utf-8') as f:
                reader = csv.reader(f, delimiter=',')
                header = next(reader)
                new_records.append(header)
                for row in reader:
                    # date,ecosystem,file_path,operation_type,last_update_time
                    file_path = row[2]
                    last_update_time = row[4]
                    if file_path == local_rela_file and (operation_type == 'updated' or operation_type == 'deleted'):
                        continue
                    else:
                        new_records.append(row)
            new_records.append(updated_records)
            with open(sync_log_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f, delimiter=',')
                writer.writerows(new_records)
        print(f"[+] Updated sync records: {updated_records}")

                    
            

def transform_validate_dir(dir_name):
    """将目录名转换为合法的目录名"""
    white_list = [
        "/", ":", "*", "?", "\"", "<", ">", "|", " ", ".", ",", "!", "~", "[", "]"
    ]
    
    for char in white_list:
        dir_name = dir_name.replace(char, '_')
    if not os.path.exists(FILE_DIR_NAME_TRANSFORM_RECORD):
        with open(FILE_DIR_NAME_TRANSFORM_RECORD, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, delimiter='\t')
            writer.writerow(['original_name', 'transformed_name'])
    # 记录转换记录
    with open(FILE_DIR_NAME_TRANSFORM_RECORD, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, delimiter='\t')
        writer.writerow([dir_name, dir_name])
    return dir_name

def summary_transform_record():
    """总结转换记录"""
    output_file = FILE_DIR_NAME_TRANSFORM_RECORD.with_suffix('.summary.json')
    output_data = {}
    with open(FILE_DIR_NAME_TRANSFORM_RECORD, 'r', encoding='utf-8') as f:
        reader = csv.reader(f, delimiter='\t')
        header = next(reader)
        for row in reader:
            origin_name = row[0]
            transformed_name = row[1]
            if origin_name not in output_data:
                output_data[origin_name] = []
            output_data[origin_name].append(transformed_name)
            # 去重
            output_data[origin_name] = list(set(output_data[origin_name]))
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, ensure_ascii=False, indent=2)
    logger.info(f"[+] Transform record summary saved to {output_file}")
            


# 同步生态系统数据
def sync_ecosystem(base_url, ecosystem, data_dir, timeout, retries, sync_log_file):
    """同步指定生态系统的漏洞数据
    Args:
        base_url: 基础URL
        ecosystem: 生态系统名称
        data_dir: 数据目录
        timeout: 超时时间
        retries: 重试次数
        sync_log_file: 同步日志文件路径
    """
    transformed_ecosystem = transform_validate_dir(ecosystem)
    ecosystem_dir = data_dir / transformed_ecosystem
    ecosystem_dir.mkdir(exist_ok=True, parents=True)
    
    # 获取远程文件列表, 这时候要用原始的 ecosystem
    remote_files = get_directory_files(base_url, ecosystem)
    if not remote_files:
        logger.warning(f"cannot get remote file list of {ecosystem}")
        return 0
    
    # 获取本地文件列表
    local_files = os.listdir(ecosystem_dir) if ecosystem_dir.exists() else []
    
    # 操作日志文件路径
    log_file_path = sync_log_file
    
    # 下载新文件或更新的文件
    updated_count = 0
    for file_info in tqdm(remote_files, desc=f"同步生态系统 {ecosystem} 的文件", total=len(remote_files)):
        file_name = file_info['name']
        remote_time = file_info['last_modified']
        # 准备输入
        ecosystem_info = file_info
        ecosystem_ = ecosystem_info['ecosystem']
        local_rela_file = os.path.join(data_dir, ecosystem_, file_name)
        # 检查是否需要更新
        # need_update, operation_type = needs_update(ecosystem_info, local_rela_file)
        need_update, updated_records = needs_update(ecosystem_info, local_rela_file)
        opcode = updated_records[3] if need_update else None
        if need_update:
            try:
                # 使用完整URL（如果有）
                if 'full_url' in file_info and file_info['full_url']:
                    file_url = file_info['full_url']
                # 回退到简单URL
                else:
                    file_url = f"{base_url}{ecosystem}/{file_name}"
                
                download_file(file_url, ecosystem_dir / file_name, timeout, retries)
                
                # 记录操作
                file_path = str(ecosystem_dir / file_name)
                record = [datetime.now().strftime('%Y-%m-%d %H:%M:%S'), ecosystem, file_path, opcode, remote_time]
                log_file_operation(ecosystem, file_path, opcode, record, log_file_path)
                updated_count += 1
            except Exception as e:
                logger.error(f"下载文件 {file_name} 到 {ecosystem} 失败: {str(e)}")
                
    
    # 检查需要删除的文件（本地有但远程没有）
    remote_file_names = [f['name'] for f in remote_files]
    for local_file in local_files:
        if local_file not in remote_file_names:
            try:
                local_file_path = ecosystem_dir / local_file
                if os.path.exists(local_file_path):
                    os.remove(local_file_path)
                    # 记录删除操作
                    file_path = str(local_file_path)
                    # ecosystem, local_rela_file, opcode, updated_records, sync_log_file
                    # ['date', 'ecosystem', 'file_path', 'operation_type', 'last_update_time']
                    record = [datetime.now().strftime('%Y-%m-%d %H:%M:%S'), ecosystem, file_path, "deleted", datetime.now().strftime('%Y-%m-%d %H:%M:%S')]
                    log_file_operation(ecosystem, file_path, "deleted", record, log_file_path)
                    updated_count += 1
            except Exception as e:
                logger.error(f"删除文件 {local_file} 失败: {str(e)}")
                
    return updated_count

# 检查文件是否需要更新
def needs_update(remote_file_info:dict, file_name):
    """判断本地文件是否需要更新
    比较内容: 
        - 文件大小
        - 文件最后修改时间
    """
    try:
        last_update_time_remote = datetime.strptime(remote_file_info["last_modified"], '%Y-%m-%d %H:%M:%S')
    except:
        print(f"[-] Warning: The last modified time of file {file_name} is incorrect: {remote_file_info['last_modified']}, using current time")
        last_update_time_remote = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ecosystem = remote_file_info["ecosystem"]
    rew_records = []
    if ecosystem == '':
        print(f"当前任务是拉取主目录中的文件,")
        ecosystem = 'all'

    # size_remote = remote_file_info["size"] # 大小可以不判断了其实
    # 如果sync文件不存在, 则需要更新
    recording_file_path = config['recording']['file_path']
    if not os.path.exists(recording_file_path):
        with File_lock:
            with open(recording_file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f, delimiter=',')
                writer.writerow(['date', 'ecosystem', 'file_path', 'operation_type', 'last_update_time'])
                # rew_records = [['date', 'ecosystem', 'file_path', 'operation_type', 'last_update_time']]
                rew_records = [datetime.now().strftime('%Y-%m-%d %H:%M:%S'), ecosystem, file_name, 'new_intro', last_update_time_remote]
        return True, rew_records
    
    # 如果文件存在, 则需要判断是否需要更新
    update_flag = False
    file_name_in = False
    file_path, operation_type = None, None
    with open(recording_file_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f, delimiter=',')
        header = next(reader)
        for row in reader:
            file_path = row[2]
            last_update_time = row[4]
            # 如果
            try:
                last_update_time = datetime.strptime(row[4], '%Y-%m-%d %H:%M:%S')
            except:
                last_update_time = datetime.strptime(row[4].split(' ')[0], '%Y-%m-%d')
            if file_path == file_name and last_update_time != last_update_time_remote:
                rew_records = [datetime.now().strftime('%Y-%m-%d %H:%M:%S'), ecosystem, file_name, 'updated', last_update_time_remote]
                update_flag = True
                continue
            elif file_path == file_name:
                file_name_in = True
    # 如果更新了, 则需要更新
    if update_flag:
        # with File_lock:
        #     with open(recording_file_path, 'w', newline='', encoding='utf-8') as f:
        #         writer = csv.writer(f, delimiter=',')
        #         writer.writerows(output_date)
        return True, rew_records
    
    # 如果文件根本不存在, 则需要更新
    if not file_name_in:
        # with File_lock:
        #     with open(recording_file_path, 'w', newline='', encoding='utf-8') as f:
        #         writer = csv.writer(f, delimiter=',')
        #         writer.writerows(output_date)
        rew_records = [datetime.now().strftime('%Y-%m-%d %H:%M:%S'), ecosystem, file_name, 'new_intro', last_update_time_remote]
        return True, rew_records

    # 如果文件存在且 last_update_time_remote 相等 则不需要更新
    return False, None

# 主同步函数
def sync_osv_data():
    """主同步函数, 同步所有OSV漏洞数据"""    
    try:
        # 创建数据目录
        data_dir = Path(config['storage']['data_dir'])
        data_dir.mkdir(exist_ok=True, parents=True)
        
        # 记录同步开始
        log_file_name = config['recording']['file_path']
        sync_log_file = log_file_name
        if not os.path.isfile(sync_log_file):
            with open(sync_log_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f, delimiter=',')
                writer.writerow(['date', 'ecosystem', 'file_path', 'operation_type', 'last_update_time'])
        
        # 获取索引页面
        base_url = config['source']['base_url']
        index_url = config['source']['index_url']
        
        # 解析生态系统列表和文件
        logger.info(f"Searching ecosystems of main page...")
        ecosystems, files_info = parse_with_playwright(index_url)
        logger.info(f"Found {len(ecosystems)} ecosystems")
        
        # 下载 ecosystems.txt
        # 确认是否需要下载
        # if 'ecosystems.txt' in files and files['ecosystems.txt']:
        # need_update, updated_records = needs_update(files, data_dir / 'ecosystems.txt')
        # local_rela_file = str(data_dir / 'ecosystems.txt')
        ecosystem_info = files_info['ecosystems.txt']
        ecosystem_ = ecosystem_info['ecosystem']
        local_rela_file = os.path.join(data_dir, ecosystem_, 'ecosystems.txt')
        need_update, updated_records = needs_update(ecosystem_info, local_rela_file)
        opcode = updated_records[3] if need_update else None
        if need_update:
            try:
                ecosystems_url = f"{base_url}ecosystems.txt"
                is_downloaded = download_file(ecosystems_url, data_dir / 'ecosystems.txt', 
                             config['sync']['timeout'], config['sync']['retry_attempts'])
                if not is_downloaded:
                    logger.info(f"ecosystems.txt 无需更新")
                else:
                    logger.info("已下载 ecosystems.txt")
                    # 记录操作
                    ecosystem = 'all'
                    log_file_operation(ecosystem, local_rela_file, opcode, updated_records, sync_log_file)
            except Exception as e:
                logger.error(f"下载 ecosystems.txt 失败: {str(e)}")
                
        
        # 下载 all.zip（如果配置允许）
        if config['storage']['download_all_zip'] and 'all.zip' in files_info and files_info['all.zip']:
            # local_rela_file = str(data_dir / 'all.zip')
            ecosystem_info = files_info['all.zip']
            ecosystem_ = ecosystem_info['ecosystem']
            local_rela_file = os.path.join(data_dir, ecosystem_, 'all.zip')
            need_update, updated_records = needs_update(ecosystem_info, local_rela_file)
            opcode = updated_records[3] if need_update else None
            try:
                all_zip_url = f"{base_url}all.zip"
                download_file(all_zip_url, data_dir / 'all.zip', 
                             config['sync']['timeout'], config['sync']['retry_attempts'])
                logger.info("已下载 all.zip")
                # 记录操作
                ecosystem = 'all'
                log_file_operation(ecosystem, local_rela_file, opcode, updated_records, sync_log_file)
            except Exception as e:
                logger.error(f"下载 all.zip 失败: {str(e)}")
        
        # 多线程处理, 所有的生态系统
        total_updated = 0
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_ecosystem = {
                executor.submit(
                    sync_ecosystem, 
                    base_url, ecosystem, data_dir, 
                    config['sync']['timeout'], 
                    config['sync']['retry_attempts'],
                    sync_log_file
                ): ecosystem for ecosystem in ecosystems
            }
            
            for future in as_completed(future_to_ecosystem):
                ecosystem = future_to_ecosystem[future]
                try:
                    updated_count = future.result()
                    total_updated += updated_count
                    logger.info(f"Ecosystem {ecosystem} updated {updated_count} files")
                except Exception as e:
                    logger.error(f"Error syncing ecosystem {ecosystem}: {str(e)}")
        # for ecosystem in ecosystems:
        #     try:
        #         updated_count = sync_ecosystem(
        #             base_url, ecosystem, data_dir, 
        #             config['sync']['timeout'], 
        #             config['sync']['retry_attempts']
        #         )
        #         total_updated += updated_count
        #         logger.info(f"生态系统 {ecosystem} 已更新 {updated_count} 个文件")
        #     except Exception as e:
        #         logger.error(f"同步生态系统 {ecosystem} 时出错: {str(e)}")
        
        logger.info(f"同步完成，共更新了 {total_updated} 个文件")
        
    except Exception as e:
        logger.error(f"同步过程中发生错误: {str(e)}")

# 主函数
def main():
    """主函数"""

    global logger, config
    
    # 加载配置
    config = load_config()
    
    # 设置日志
    logger = setup_logging(config['storage']['logs_dir'])
    
    # 确保数据目录存在
    data_dir = Path(config['storage']['data_dir'])
    data_dir.mkdir(exist_ok=True, parents=True)
    
    # 立即执行一次同步
    logger.info("Daily Sync Start...")
    sync_osv_data()
    logger.info("Daily Sync Done...")


def with_playwright(url, callback):
    """使用 playwright 加载页面并执行回调函数
    
    Args:
        url: 要访问的URL
        callback: 接受页面对象的回调函数，用于处理页面
        
    Returns:
        回调函数的返回值
    """
    with sync_playwright() as p:
        # 根据配置选择浏览器类型
        browser_type = config['browser']['browser_type']
        if browser_type == 'firefox':
            browser_engine = p.firefox
        elif browser_type == 'webkit':
            browser_engine = p.webkit
        else:
            browser_engine = p.chromium
        
        # 设置浏览器选项
        browser = browser_engine.launch(
            headless=config['browser']['headless'],
            args=config['browser']['options']['args']
        )
        
        # 设置上下文
        context = browser.new_context(
            viewport=config['browser']['viewport']
        )
        
        # 创建新页面
        page = context.new_page()
        
        # 设置超时
        page.set_default_timeout(config['browser']['timeout'])
        
        try:
            # 访问 URL
            page.goto(url, timeout=config['browser']['timeout'])
            
            # 等待表格元素加载完成
            page.wait_for_selector("table tr", timeout=config['browser']['timeout'])
            
            # 等待网络请求完成，确保JS执行结束
            page.wait_for_load_state('networkidle', timeout=config['browser']['timeout'])
            

            # 执行回调处理页面
            result = callback(page)
            
            return result
        except Exception as e:
            logger.error(f"Playwright 操作失败: {str(e)}")
            raise
        finally:
            # 确保资源被释放
            page.close()
            context.close()
            browser.close()


def parse_with_playwright(url):
    """解析OSV索引页面, 获取生态系统列表和文件信息"""
    logger.info(f"Fetching {url} page...")
    try:
        def process_page(page):
            # 获取生态系统目录
            ecosystems = []
            folder_elements = page.query_selector_all("td a[href*='?prefix=']")
            for elem in folder_elements:
                folder_name = elem.inner_text()
                if folder_name != 'Parent Directory':
                    ecosystems.append(folder_name.rstrip('/'))
            
            # 获取文件, 这里面的 key 是 文件名, value 是 最后修改时间, 文件大小
            files = {'all.zip': None, 'ecosystems.txt': None}
            for file_name in files.keys():
                file_elements = page.query_selector_all(f"td a:text-is('{file_name}')")
                if file_elements:
                    # 获取上级行的日期和大小信息
                    row_data = elem.evaluate("""el => {
                        const row = el.closest('tr');
                        const cells = row.querySelectorAll('td');
                        return {
                            date: cells[2].innerText,
                            size: cells[3].innerText
                        };
                    }""")
                    date_td = row_data['date']
                    size_td = row_data['size']
                    
                    files[file_name] = {
                        'name': file_name,
                        'last_modified': date_td,
                        'size': size_td,
                        'ecosystem': ''
                    }
            
            return ecosystems, files
        return with_playwright(url, process_page)
    except Exception as e:
        logger.error(f"解析索引页面失败: {str(e)}")
        return [], {}

if __name__ == "__main__":
    # root = os.path.join(os.getcwd(), 'data')
    # for subdir in os.listdir(root):
    #     path_ = os.path.join(root, subdir)
    #     if os.path.isfile(path_):
    #         continue
    #     transformed_dir = transform_validate_dir(subdir)
    #     os.rename(path_, os.path.join(root, transformed_dir))
    #     print(f"rename {subdir} to {transformed_dir}")
    #     # for subsub in os.listdir(path_):
    #     #     path__ = os.path.join(path_, subsub)
    #     #     if os.path.isdir(path__):
    #     #         shutil.rmtree(path__)
    #     #         print(f"remove extra dir{path__}")
    # 将 sync_recording.csv 中的 目录名转换为合法的
    # sync_recording_file = os.path.join(os.getcwd(), 'sync_recording.csv')
    # new_output = []
    # with open(sync_recording_file, 'r', encoding='utf-8') as f:
    #     reader = csv.reader(f, delimiter=',')
    #     header = next(reader)
    #     for row in reader:
    #         date,ecosystem,file_path,operation_type,last_update_time = row
    #         parts = file_path.split('/')
    #         new_file_path = ''
    #         for part in parts[:-1]:
    #             part_ = transform_validate_dir(part)
    #             new_file_path += part_ + '/'
    #         new_file_path = new_file_path+parts[-1]
    #         new_output.append([date, ecosystem, new_file_path, operation_type, last_update_time])
    # with open(sync_recording_file, 'w', newline='', encoding='utf-8') as f:
    #     writer = csv.writer(f, delimiter=',')
    #     writer.writerow(header)
    #     writer.writerows(new_output)
    # 验证 sync_recording.csv 中的 目录名是否合法
    # sync_recording_file = os.path.join(os.getcwd(), 'sync_recording.csv')
    # with open(sync_recording_file, 'r', encoding='utf-8') as f:
    #     reader = csv.reader(f, delimiter=',')
    #     header = next(reader)
    #     for row in reader:
    #         date,ecosystem,file_path,operation_type,last_update_time = row
    #         exist = os.path.exists(file_path)
    #         if not exist:
    #             print(f"文件 {file_path} 不存在")
    #         else:
    #             print(f"文件 {file_path} 存在")
    # exit(1)
    main() 