#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
下载器模块，负责文件下载功能
"""

import csv
import json
import logging
import os
import threading
import zipfile
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from tqdm import tqdm


class Downloader:
    """文件下载器类"""

    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """初始化下载器

        Args:
            config: 配置信息
            logger: 日志对象
        """
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        self.file_lock = threading.Lock()

    def check_validation(self, path):
        """根据文件后缀验证文件完整性

        Args:
            path: 文件路径

        Raises:
            Exception: 文件无效时抛出异常
        """
        file_path = Path(path) if isinstance(path, str) else path
        try:
            if file_path.suffix.lower() == ".json":
                with open(file_path, "r") as f:
                    json.load(f)  # 尝试解析JSON以验证完整性
            elif file_path.suffix.lower() in [".csv", ".txt"]:
                with open(file_path, "r") as f:
                    reader = csv.reader(f)
                    list(reader)  # 尝试读取所有行以验证完整性
            elif file_path.suffix.lower() == ".zip":
                with zipfile.ZipFile(file_path, "r") as f:
                    f.testzip()
        except Exception as e:
            self.logger.error(f"文件 {path} 无效: {e}, 准备重试...")
            # 删除损毁文件
            if os.path.exists(file_path):
                os.remove(file_path)
            raise Exception(f"文件无效: {e}")

    def download_file(
        self, url: str, dest_path, timeout: int = None, retries: int = None
    ):
        """下载文件到指定路径

        Args:
            url: 文件下载URL
            dest_path: 目标保存路径
            timeout: 超时时间（毫秒），如果不指定则使用配置中的值
            retries: 重试次数，如果不指定则使用配置中的值

        Returns:
            bool: 下载是否成功
        """
        if timeout is None:
            timeout = self.config["sync"]["timeout"]
        if retries is None:
            retries = self.config["sync"]["retry_attempts"]

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
                            desc=f"下载 {url}",
                            total=total_size,
                            unit="B",
                            unit_scale=True,
                        ):
                            if chunk:
                                f.write(chunk)
                    self.logger.info(f"下载文件 {url} 到 {temp_file_path} 成功")

                    # 验证文件完整性
                    self.check_validation(temp_file_path)

                    # 如果是 ecosystems.txt 文件, 则需要验证内容与本地文件是否发生改变
                    if dest_path.name == "ecosystems.txt" and dest_path.exists():
                        with open(temp_file_path, "r") as f:
                            reader = csv.reader(f)
                            remote_data = [row[0] for row in reader]
                            remote_data_set = set(remote_data)
                        with open(dest_path, "r") as f:
                            reader = csv.reader(f)
                            local_data = [row[0] for row in reader]
                            local_data_set = set(local_data)
                        if remote_data_set != local_data_set:
                            self.logger.info(
                                f"远程ecosystems.txt与本地文件不同，更新中..."
                            )
                        else:
                            self.logger.info(
                                f"远程ecosystems.txt与本地文件相同，跳过..."
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
                            self.logger.warning(f"创建备份文件失败: {str(e)}")
                            raise Exception(f"创建备份文件失败: {str(e)}")

                    # 重命名临时文件为目标文件
                    os.rename(temp_file_path, dest_path)

                    # 删除备份文件（如果存在）
                    backup_path = dest_path.with_suffix(".bak")
                    if os.path.exists(backup_path):
                        try:
                            os.remove(backup_path)
                        except Exception as e:
                            self.logger.warning(f"删除备份文件失败: {str(e)}，忽略...")
                    return True
            except Exception as e:
                self.logger.error(
                    f"下载 {url} 失败，重试 {attempt+1}/{retries}: {str(e)}"
                )
                # 删除临时文件
                if os.path.exists(temp_file_path):
                    try:
                        os.remove(temp_file_path)
                    except Exception as e2:
                        self.logger.error(f"删除临时文件失败: {e2}，忽略...")
                        pass
                # 下载失败的情况, 如果存在备份文件并且主文件不存在, 将备份恢复为主文件
                if attempt == retries - 1:
                    # 恢复备份（如果存在）
                    backup_path = dest_path.with_suffix(".bak")
                    if os.path.exists(backup_path) and not os.path.exists(dest_path):
                        try:
                            os.rename(backup_path, dest_path)
                            self.logger.info(f"恢复 {dest_path} 的备份")
                        except Exception as e:
                            self.logger.error(f"恢复备份文件失败: {str(e)}")
                import time

                time.sleep(2 * attempt)  # 指数退避
        return False
