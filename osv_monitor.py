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
# from selenium import webdriver
# from selenium.webdriver.chrome.options import Options
# from selenium.webdriver.common.by import By
# from selenium.webdriver.support.ui import WebDriverWait
# from selenium.webdriver.support import expected_conditions as EC
# from selenium.webdriver.chrome.service import Service

# 配置日志
def setup_logging(logs_dir):
    """设置日志记录"""
    logs_dir = Path(logs_dir)
    logs_dir.mkdir(exist_ok=True, parents=True)
    
    log_file = logs_dir / f"osv_monitor_{datetime.datetime.now().strftime('%Y%m%d')}.log"
    
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

# 解析索引页面
def parse_index_page(html_content):
    """解析OSV索引页面, 获取生态系统列表和文件信息"""
    soup = BeautifulSoup(html_content, 'lxml')
    table = soup.find('table')
    
    ecosystems = []
    files = {'all.zip': None, 'ecosystems.txt': None}
    
    if table:
        rows = table.find_all('tr')[2:]  # 跳过表头和空行
        for row in rows:
            cols = row.find_all('td')
            if len(cols) >= 2:
                name = cols[0].text.strip()
                if name.endswith('/') and name != '../':
                    # 这是一个生态系统目录
                    ecosystems.append(name.rstrip('/'))
                elif name in files:
                    # 这是一个我们关注的文件
                    last_modified = cols[1].text.strip() if len(cols) > 1 else ""
                    size = cols[2].text.strip() if len(cols) > 2 else ""
                    files[name] = {'last_modified': last_modified, 'size': size}
    
    return ecosystems, files

# 下载文件
def download_file(url, dest_path, timeout=300, retries=3):
    """下载文件到指定路径，支持重试和进度条显示"""
    for attempt in range(retries):
        try:
            with requests.get(url, stream=True, timeout=timeout) as r:
                r.raise_for_status()
                total_size = int(r.headers.get('content-length', 0))
                dest_path.parent.mkdir(exist_ok=True, parents=True)
                
                with open(dest_path, 'wb') as f:
                    # with tqdm(total=total_size, unit='B', unit_scale=True, desc=dest_path.name) as pbar:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            # pbar.update(len(chunk))
                return True
        except Exception as e:
            logger.error(f"下载 {url} 失败，尝试 {attempt+1}/{retries}: {str(e)}")
            if attempt == retries - 1:
                raise
            time.sleep(2 ** attempt)  # 指数退避
    return False

# 获取目录文件列表
def get_directory_files(base_url, ecosystem):
    """获取指定生态系统目录下的文件列表"""
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
                        'full_url': href
                    })
            
            return files
        
        return with_playwright(url, process_page)
    except Exception as e:
        logger.error(f"获取目录 {ecosystem} 的文件列表失败: {str(e)}")
        return []

# 同步生态系统数据
def sync_ecosystem(base_url, ecosystem, data_dir, timeout, retries):
    """同步指定生态系统的漏洞数据"""
    ecosystem_dir = data_dir / ecosystem
    ecosystem_dir.mkdir(exist_ok=True, parents=True)
    
    # 获取远程文件列表
    remote_files = get_directory_files(base_url, ecosystem)
    if not remote_files:
        logger.warning(f"无法获取生态系统 {ecosystem} 的远程文件列表")
        return 0
    
    # 获取本地文件列表
    # local_files = {f.name: f.stat().st_mtime for f in data_dir.glob('*') if f.is_file()}
    local_files = os.listdir(ecosystem_dir)
    
    # 下载新文件或更新的文件
    updated_count = 0
    for file_info in tqdm(remote_files, desc=f"同步生态系统 {ecosystem} 的文件", total=len(remote_files)):
        file_name = file_info['name']
        remote_time = file_info['last_modified']
        
        # 简单比较是否需要更新，可以基于修改时间或大小
        if file_name not in local_files:
            try:
                # 使用完整URL（如果有）
                if 'full_url' in file_info and file_info['full_url']:
                    file_url = file_info['full_url']
                # 回退到简单URL
                else:
                    file_url = f"{base_url}{ecosystem}/{file_name}"
                
                download_file(file_url, ecosystem_dir / file_name, timeout, retries)
                updated_count += 1
            except Exception as e:
                logger.error(f"下载文件 {file_name} 到 {ecosystem} 失败: {str(e)}")
                try:
                    if os.path.exists(ecosystem_dir / file_name):
                        os.remove(ecosystem_dir / file_name)
                except:
                    pass
                
    return updated_count

# 检查文件是否需要更新
def needs_update(remote_time_str, local_timestamp):
    """判断本地文件是否需要更新"""
    # 这里需要根据实际的时间格式解析远程时间字符串
    # 简化版：总是返回 True 以确保更新
    # 实际应用中，应该解析远程时间并与本地时间比较
    return True

# 主同步函数
def sync_osv_data():
    """主同步函数, 同步所有OSV漏洞数据"""
    logger.info("开始同步 OSV 漏洞数据...")
    
    try:
        # 创建数据目录
        data_dir = Path(config['storage']['data_dir'])
        data_dir.mkdir(exist_ok=True, parents=True)
        
        # 获取索引页面
        base_url = config['source']['base_url']
        index_url = config['source']['index_url']
        
        # response = requests.get(index_url, timeout=config['sync']['timeout'])
        # response.raise_for_status()
        
        # 解析生态系统列表和文件
        ecosystems, files = parse_with_playwright(index_url)
        logger.info(f"发现 {len(ecosystems)} 个生态系统")
        
        # 下载 ecosystems.txt
        if 'ecosystems.txt' in files and files['ecosystems.txt']:
            try:
                ecosystems_url = f"{base_url}ecosystems.txt"
                download_file(ecosystems_url, data_dir / 'ecosystems.txt', 
                             config['sync']['timeout'], config['sync']['retry_attempts'])
                logger.info("已下载 ecosystems.txt")
            except Exception as e:
                logger.error(f"下载 ecosystems.txt 失败: {str(e)}")
        
        # 下载 all.zip（如果配置允许）
        if config['storage']['download_all_zip'] and 'all.zip' in files and files['all.zip']:
            try:
                all_zip_url = f"{base_url}all.zip"
                download_file(all_zip_url, data_dir / 'all.zip', 
                             config['sync']['timeout'], config['sync']['retry_attempts'])
                logger.info("已下载 all.zip")
            except Exception as e:
                logger.error(f"下载 all.zip 失败: {str(e)}")
        
        
        total_updated = 0
        # with ThreadPoolExecutor(max_workers=5) as executor:
        #     future_to_ecosystem = {
        #         executor.submit(
        #             sync_ecosystem, 
        #             base_url, ecosystem, data_dir, 
        #             config['sync']['timeout'], 
        #             config['sync']['retry_attempts']
        #         ): ecosystem for ecosystem in ecosystems
        #     }
            
        #     for future in as_completed(future_to_ecosystem):
        #         ecosystem = future_to_ecosystem[future]
        #         try:
        #             updated_count = future.result()
        #             total_updated += updated_count
        #             logger.info(f"生态系统 {ecosystem} 已更新 {updated_count} 个文件")
        #         except Exception as e:
        #             logger.error(f"同步生态系统 {ecosystem} 时出错: {str(e)}")
        for ecosystem in ecosystems:
            try:
                updated_count = sync_ecosystem(
                    base_url, ecosystem, data_dir, 
                    config['sync']['timeout'], 
                    config['sync']['retry_attempts']
                )
                total_updated += updated_count
                logger.info(f"生态系统 {ecosystem} 已更新 {updated_count} 个文件")
            except Exception as e:
                logger.error(f"同步生态系统 {ecosystem} 时出错: {str(e)}")
        
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
    logger.info("首次启动同步...")
    sync_osv_data()
    
    # 设置定时任务
    interval_hours = config['sync']['interval_hours']
    logger.info(f"设置定时任务，每 {interval_hours} 小时同步一次")
    schedule.every(interval_hours).hours.do(sync_osv_data)
    
    # 循环运行定时任务
    while True:
        schedule.run_pending()
        time.sleep(60)  # 每分钟检查一次


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
    try:
        def process_page(page):
            # 获取生态系统目录
            ecosystems = []
            folder_elements = page.query_selector_all("td a[href*='?prefix=']")
            for elem in folder_elements:
                folder_name = elem.inner_text()
                if folder_name != 'Parent Directory':
                    ecosystems.append(folder_name.rstrip('/'))
            
            # 获取文件
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
                        'last_modified': date_td,
                        'size': size_td
                    }
            
            return ecosystems, files
        
        return with_playwright(url, process_page)
    except Exception as e:
        logger.error(f"解析索引页面失败: {str(e)}")
        return [], {}

if __name__ == "__main__":
    main() 