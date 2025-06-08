#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OSV Vulnerability Database Sync Module
For synchronizing vulnerability data from https://storage.googleapis.com/osv-vulnerabilities/index.html
"""

import csv
import datetime
import json
import logging
import os
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pandas as pd
import requests
import yaml
from bs4 import BeautifulSoup
from playwright.sync_api import Page, sync_playwright
from tqdm import tqdm

from osv_sync.downloader import Downloader

# File lock
File_lock = threading.Lock()


# Validate file integrity
def check_validation(path, logger):
    """Check if a file is corrupted based on its extension, currently supports json, csv, text, zip"""
    file_path = Path(path) if type(path) is str else path
    try:
        if file_path.suffix.lower() == ".json":
            with open(file_path, "r") as f:
                json.load(f)  # Try to parse JSON to verify integrity
        elif file_path.suffix.lower() in [".csv", ".txt"]:
            with open(file_path, "r") as f:
                reader = csv.reader(f)
        elif file_path.suffix.lower() == ".zip":
            with zipfile.ZipFile(file_path, "r") as f:
                f.testzip()
    except Exception as e:
        logger.error(f"File {path} is invalid: {e}, retrying...")
        # Delete corrupted file
        if os.path.exists(file_path):
            os.remove(file_path)
        raise Exception("Invalid File")


# Download file
def download_file(url, dest_path, timeout=3000, retries=3, logger=None):
    """下载文件到指定路径，支持重试和进度条显示
    arg:
        - url: 文件下载 url
        - dest_path: 本地存储路径
        - timeout: 等待时长
        - retries: 重试次数
        - logger: 日志对象
    return: True|False 是否下载成功
    ps:
      - 由于可能存在网络问题, 导致下载过程中失败, 或者下载到一半文件反而导致原始文件受损, 加入临时文件机制.
      - 由于会多线程同时下载, 要确保下载文件目录(文件名)不会发生冲突
    """
    # 创建临时文件路径
    if isinstance(dest_path, str):
        dest_path = Path(dest_path)
    tmp_parent = dest_path.parent
    tmp_file_name = dest_path.name
    dest_path = tmp_parent / tmp_file_name
    temp_file_path = dest_path.with_suffix(".tmp")

    for attempt in range(retries):
        try:
            with requests.get(url, stream=True, timeout=timeout) as r:
                r.raise_for_status()
                dest_path.parent.mkdir(exist_ok=True, parents=True)

                # 下载到临时文件
                with open(temp_file_path, "wb") as f:
                    total_size = int(r.headers.get("content-length", 0))
                    for chunk in tqdm(
                        r.iter_content(chunk_size=8192),
                        desc=f"Downloading {url}",
                        total=total_size,
                        unit="B",
                        unit_scale=True,
                    ):
                        if chunk:
                            f.write(chunk)
                logger.info(f"下载文件 {url} 到 {temp_file_path} 成功")

                # 验证文件完整性
                check_validation(temp_file_path, logger)

                # 如果是 ecosystems.txt 文件, 则需要验证内容与本地文件是否发生改变
                if dest_path.name == "ecosystems.txt":
                    with open(temp_file_path, "r") as f:
                        reader = csv.reader(f)
                        remote_data = [row[0] for row in reader]
                        remote_data_set = set(remote_data)
                    with open(dest_path, "r") as f:
                        reader = csv.reader(f)
                        local_data = [row[0] for row in reader]
                        local_data_set = set(local_data)
                    if remote_data_set != local_data_set:
                        logger.info(
                            f"Remote ecosystems.txt differs from local file, updating..."
                        )
                    else:
                        logger.info(
                            f"Remote ecosystems.txt matches local file, skipping..."
                        )
                        os.remove(temp_file_path)
                        return False

                # 下载成功，安全地替换目标文件
                if os.path.exists(dest_path):
                    # 创建备份，以防万一
                    backup_path = dest_path.with_suffix(".bak")
                    try:
                        if os.path.exists(backup_path):
                            os.remove(backup_path)
                        os.rename(dest_path, backup_path)
                    except Exception as e:
                        logger.warning(f"Creating backup file failed: {str(e)}")
                        raise Exception(f"Creating backup file failed: {str(e)}")

                # 重命名临时文件为目标文件
                os.rename(temp_file_path, dest_path)

                # 删除备份文件（如果存在）
                backup_path = dest_path.with_suffix(".bak")
                if os.path.exists(backup_path):
                    try:
                        os.remove(backup_path)
                    except Exception as e:
                        logger.warning(
                            f"Deleting backup file failed: {str(e)}, ignoring..."
                        )
                return True
        except Exception as e:
            logger.error(
                f"Dowloing {url} failed, retrying {attempt+1}/{retries}: {str(e)}"
            )
            # 删除临时文件
            if os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                except Exception as e2:
                    logger.error(f"Deleting tmp file failed: {e2}, ignoring...")
                    pass
            # 下载失败的情况, 如果存在备份文件并且主文件不存在, 将备份恢复为主文件
            if attempt == retries - 1:
                # 恢复备份（如果存在）
                backup_path = dest_path.with_suffix(".bak")
                if os.path.exists(backup_path) and not os.path.exists(dest_path):
                    try:
                        os.rename(backup_path, dest_path)
                        logger.info(f"恢复 {dest_path} 的备份")
                    except Exception as e:
                        logger.error(f"恢复备份文件失败: {str(e)}")
            time.sleep(2 * attempt)  # 指数退避
    return False


def with_playwright(url: str, callback, config: Dict[str, Any], logger: logging.Logger):
    """使用 playwright 加载页面并执行回调函数

    Args:
        url: 要访问的URL
        callback: 接受页面对象的回调函数，用于处理页面
        config: 配置信息
        logger: 日志对象

    Returns:
        回调函数的返回值
    """
    with sync_playwright() as p:
        # 根据配置选择浏览器类型
        browser_type = config["browser"]["browser_type"]
        if browser_type == "firefox":
            browser_engine = p.firefox
        elif browser_type == "webkit":
            browser_engine = p.webkit
        else:
            browser_engine = p.chromium

        # 设置浏览器选项
        browser = browser_engine.launch(
            headless=config["browser"]["headless"],
            args=config["browser"]["options"]["args"],
        )

        # 设置上下文
        context = browser.new_context(viewport=config["browser"]["viewport"])

        # 创建新页面
        page = context.new_page()

        # 设置超时
        page.set_default_timeout(config["browser"]["timeout"])

        try:
            # 访问 URL
            page.goto(url, timeout=config["browser"]["timeout"])

            # 等待表格元素加载完成
            page.wait_for_selector("table tr", timeout=config["browser"]["timeout"])

            # 等待网络请求完成，确保JS执行结束
            page.wait_for_load_state(
                "networkidle", timeout=config["browser"]["timeout"]
            )

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


def parse_with_playwright(
    url: str, config: Dict[str, Any], logger: logging.Logger
) -> Tuple[List[str], Dict[str, Any]]:
    """解析OSV索引页面, 获取生态系统列表和文件信息

    Args:
        url: 要访问的URL
        config: 配置信息
        logger: 日志对象

    Returns:
        tuple: (ecosystems, files_info)
    """
    logger.info(f"正在获取 {url} 页面...")
    try:

        def process_page(page: Page):
            # 获取生态系统目录
            ecosystems = []
            folder_elements = page.query_selector_all("td a[href*='?prefix=']")
            for elem in folder_elements:
                folder_name = elem.inner_text()
                if folder_name != "Parent Directory":
                    ecosystems.append(folder_name.rstrip("/"))

            # 获取文件
            files = {"all.zip": None, "ecosystems.txt": None}
            for file_name in files.keys():
                file_elements = page.query_selector_all(f"td a:text-is('{file_name}')")
                if file_elements:
                    # 获取上级行的日期和大小信息
                    file_element = file_elements[0]
                    row_data = file_element.evaluate(
                        """el => {
                        const row = el.closest('tr');
                        const cells = row.querySelectorAll('td');
                        return {
                            name: el.textContent,
                            date: cells[2].textContent,
                            size: cells[1].textContent
                        };
                    }"""
                    )

                    files[file_name] = {
                        "name": row_data["name"],
                        "last_modified": row_data["date"],
                        "size": row_data["size"],
                        "ecosystem": "",
                        "url": f"{config['source']['base_url']}/{file_name}",
                    }

            # 转换信息到结构化数据
            files_info = {}
            for file_name, file_info in files.items():
                if file_info:
                    files_info[file_name] = file_info

            return ecosystems, files_info

        return with_playwright(url, process_page, config, logger)
    except Exception as e:
        logger.error(f"解析OSV索引页面失败: {str(e)}")
        raise


def log_file_operation(
    last_modified_time: datetime, config: Dict[str, Any], logger: logging.Logger
):
    """记录文件操作到日志文件
    Args:
        last_modified_time: 最后修改时间
        config: 配置信息
        logger: 日志对象
    """
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    all_zip_path = Path("data") / "all.zip"
    sync_log_file = config["recording"]["file_path"]

    # 确保日志目录存在
    Path(sync_log_file).parent.mkdir(exist_ok=True, parents=True)

    # 检查文件是否存在，不存在则创建并添加表头
    file_exists = os.path.isfile(sync_log_file)
    with open(sync_log_file, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter=",")
        # 如果文件不存在, 则创建并添加表头
        if not file_exists:
            writer.writerow(["date", "file_rela_path", "last_modified_time"])
        writer.writerow([current_time, str(all_zip_path), last_modified_time])

    logger.info(f"[+] 更新同步 all.zip 最后修改时间: {last_modified_time}")


def check_all_zip_update(last_modified_time: datetime, config: Dict[str, Any]) -> bool:
    """检查 all.zip 是否需要更新
    Args:
        last_modified_time: 最后修改时间
        config: 配置信息
    Returns:
        bool: 是否需要更新
    """
    sync_log_file = config["recording"]["file_path"]
    if not os.path.exists(sync_log_file) or os.stat(sync_log_file).st_size == 0:
        return True

    try:
        with open(sync_log_file, "r", encoding="utf-8") as f:
            reader = csv.reader(f, delimiter=",")
            headers = next(reader)  # 跳过表头

            # 获取最后一条记录
            last_record = None
            for row in reader:
                if len(row) >= 3:  # 确保行有足够的列
                    last_record = row[2]  # 最后修改时间在第三列

            if not last_record:
                return True

            last_record_time = datetime.strptime(last_record, "%Y-%m-%d %H:%M:%S")
            if last_record_time != last_modified_time:
                return True
            else:
                return False
    except (FileNotFoundError, IndexError, ValueError) as e:
        # 如果文件不存在或者解析出错，则认为需要更新
        return True


def download_sub_zip(files_info, logger, config, data_dir, ecosystem=None):
    # 获取 all.zip 的 last_modified 时间
    all_zip_last_modified = (
        files_info["all.zip"]["last_modified"]
        if ecosystem is None
        else files_info[ecosystem]["last_modified"]
    )
    all_zip_last_modified = datetime.strptime(
        all_zip_last_modified, "%Y-%m-%d %H:%M:%S"
    )
    # https://www.googleapis.com/download/storage/v1/b/osv-vulnerabilities/o/all.zip?&alt=media
    # https://www.googleapis.com/download/storage/v1/b/osv-vulnerabilities/o/npm%2Fall.zip?&alt=media
    sub_zip_url = f"{config['source']['base_url']}/{files_info['all.zip']['name']}"
    # 检查all.zip是否需要更新
    if check_all_zip_update(all_zip_last_modified, config):
        logger.info(f"all.zip 需要更新")
    else:
        logger.info(f"all.zip 已经是最新版本，跳过同步")
        logger.info(f"[+] 同步 OSV 数据完成")
        return False

    # 下载 all.zip
    all_zip_info = files_info.get("all.zip", None)
    if all_zip_info is None:
        logger.error(f"OSV 数据库中不存在 all.zip")
        raise Exception("OSV 数据库中不存在 all.zip")

    # 创建下载器
    downloader = Downloader(config, logger)

    # 下载all.zip文件
    local_file = data_dir / "all.zip"
    if not downloader.download_file(url=sub_zip_url, dest_path=local_file):
        logger.error(f"下载 all.zip 失败")
        raise Exception("下载 all.zip 失败")
    else:
        # 记录只需要记录最后更新日期
        log_file_operation(all_zip_last_modified, config, logger)
        logger.info(f"已下载 all.zip")

    return True
def sync_osv_data(config: Dict[str, Any], logger: logging.Logger, data_dir: Path):
    """主同步函数, 同步所有OSV漏洞数据
    Args:
        config: 配置信息
        logger: 日志对象
        data_dir: 数据目录
    """
    try:
        # 确保数据目录存在
        data_dir.mkdir(exist_ok=True, parents=True)

        # 记录同步开始
        sync_log_file = config["recording"]["file_path"]
        Path(sync_log_file).parent.mkdir(exist_ok=True, parents=True)

        if not os.path.isfile(sync_log_file):
            with open(sync_log_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f, delimiter=",")
                writer.writerow(["date", "file_rela_path", "last_modified_time"])

        # 获取索引页面
        base_url = config["source"]["base_url"]
        index_url = config["source"]["index_url"]
        all_zip_url = config["source"]["all_zip_url"]

        # 解析生态系统列表和文件
        logger.info(f"正在搜索主页的生态系统列表...")
        ecosystems, files_info = parse_with_playwright(index_url, config, logger)
        logger.info(f"找到 {len(ecosystems)} 个生态系统")
        # 如果全下载，否则下载只下载外层 all.zip
        # for ecosystem in ecosystems:
        #     download_sub_zip(files_info, logger, config, data_dir, ecosystem)
        try:
            result = download_sub_zip(files_info, logger, config, data_dir)
            logger.info(f"[+] 同步 OSV 数据完成")
            return result
        except Exception as e:
            logger.error(f"[-] 同步 OSV 数据出错: {str(e)}")
            raise

    except Exception as e:
        logger.error(f"[-] 同步 OSV 数据出错: {str(e)}")
        raise
