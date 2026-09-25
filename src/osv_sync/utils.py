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


def shard_of(name: str) -> str:
    """★2026-09-25 分片键:文件名里第一个 '-' 之前的 id 前缀(CVE / GHSA / MAL / PYSEC …),没有 '-' 的归 OTHER。
    GitHub 对单个树对象有 50 MB 上限:平铺的 data/all_vuln 到 1,054,541 个文件时树对象 52,848,877 字节,推送被拒
    (「每日OSV数据同步」自 2026-09-22 起每轮失败)。按前缀分片后最大的 CVE 目录约 24 万文件、树对象 ≈10 MB。"""
    stem = Path(name).name
    if stem.endswith(".json"):
        stem = stem[:-5]
    head, sep, _ = stem.partition("-")
    return head if sep and head else "OTHER"


def unzip_osv_data(zip_path: Path, data_dir: Path, exclude_prefixes: Sequence[str] = ()) -> Dict[str, int]:
    """解压缩OSV数据文件到 data/all_vuln/<PREFIX>/<ID>.json(按 id 前缀分片)

    Args:
        zip_path: 压缩包路径
        data_dir: 解压目标目录
        exclude_prefixes: 文件名以这些前缀开头的条目不解压(config storage.exclude_prefixes)。
            ★2026-09-07 12:00 起上游 all.zip 一次性多出 41.6 万个 CGA-*(Chainguard,pkg:apk)通告,
            一次 commit 百万文件,runner 上 commit/push 跑不完,同步连续失败两天;下游不消费 apk 通告。

    ★2026-09-25 分片:见 shard_of。首次分片轮会把顶层残留的平铺 *.json 删掉(flat_removed),
      git 看到的是 D(平铺)+ A(分片)同 id —— 下游 data-infra 的 deleted_record_ids 对 D+A 同 id 不记删除,
      changed_json_files 会把分片路径当新增重导一次(幂等)。

    Returns:
        {"extracted": n, "skipped": m, "flat_removed": k}

    Raises:
        zipfile.BadZipFile: 如果压缩文件格式无效
        PermissionError: 如果没有写入目标目录的权限
    """
    all_dir = data_dir / Path("all_vuln")
    all_dir.mkdir(exist_ok=True, parents=True)
    prefixes = tuple(exclude_prefixes or ())
    extracted = skipped = 0
    try:
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            made: set = set()
            for member in zip_ref.infolist():
                if member.is_dir():
                    continue
                name = Path(member.filename).name
                if prefixes and name.startswith(prefixes):
                    skipped += 1
                    continue
                shard_dir = all_dir / shard_of(name)
                if shard_dir not in made:
                    shard_dir.mkdir(exist_ok=True)
                    made.add(shard_dir)
                with zip_ref.open(member) as src, open(shard_dir / name, "wb") as dst:
                    dst.write(src.read())
                extracted += 1
        flat_removed = 0
        for stale in all_dir.glob("*.json"):            # 旧平铺布局的残留,只在顶层
            stale.unlink()
            flat_removed += 1
        return {"extracted": extracted, "skipped": skipped, "flat_removed": flat_removed}
    except zipfile.BadZipFile as e:
        raise zipfile.BadZipFile(f"无效的压缩文件: {zip_path}") from e
    except PermissionError as e:
        raise PermissionError(f"无权写入目标目录: {all_dir}") from e
