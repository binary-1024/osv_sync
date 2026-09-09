#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
工具模块，包含通用功能
"""

import logging
import os
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, cast, Sequence

import yaml


def setup_logging(logs_dir: str | Path) -> logging.Logger:
    """设置日志记录

    Args:
        logs_dir: 日志目录路径

    Returns:
        logging.Logger: 日志对象
    """
    logs_dir = Path(logs_dir)
    logs_dir.mkdir(exist_ok=True, parents=True)

    log_file = logs_dir / f"osv_monitor_{datetime.now().strftime('%Y%m%d')}.log"

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(),
        ],
        encoding="utf-8",
    )
    return logging.getLogger("osv_monitor")


def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """从YAML文件加载配置

    Args:
        config_path: 配置文件路径

    Returns:
        dict: 配置信息
    """
    config_path = os.path.join(os.getcwd(), config_path)
    with open(config_path, "r", encoding="utf-8") as f:
        return cast(Dict[str, Any], yaml.safe_load(f))


def unzip_osv_data(zip_path: Path, data_dir: Path, exclude_prefixes: Sequence[str] = ()) -> Dict[str, int]:
    """解压缩OSV数据文件

    Args:
        zip_path: 压缩包路径
        data_dir: 解压目标目录
        exclude_prefixes: 文件名以这些前缀开头的条目不解压(config storage.exclude_prefixes)。
            ★2026-09-07 12:00 起上游 all.zip 一次性多出 41.6 万个 CGA-*(Chainguard,pkg:apk)通告,
            一次 commit 百万文件,runner 上 commit/push 跑不完,同步连续失败两天;下游不消费 apk 通告。

    Returns:
        {"extracted": n, "skipped": m}

    Raises:
        zipfile.BadZipFile: 如果压缩文件格式无效
        PermissionError: 如果没有写入目标目录的权限
    """
    # 确保目标目录存在
    all_dir = data_dir / Path("all_vuln")
    all_dir.mkdir(exist_ok=True, parents=True)
    prefixes = tuple(exclude_prefixes or ())

    try:
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            if not prefixes:
                zip_ref.extractall(all_dir)
                return {"extracted": len(zip_ref.namelist()), "skipped": 0}
            keep = [n for n in zip_ref.namelist() if not Path(n).name.startswith(prefixes)]
            zip_ref.extractall(all_dir, members=keep)
            return {"extracted": len(keep), "skipped": len(zip_ref.namelist()) - len(keep)}
    except zipfile.BadZipFile as e:
        raise zipfile.BadZipFile(f"无效的压缩文件: {zip_path}") from e
    except PermissionError as e:
        raise PermissionError(f"无权写入目标目录: {all_dir}") from e
