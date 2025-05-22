#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
数据模型和类型定义模块
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class FileInfo:
    """文件信息类"""

    name: str
    last_modified: datetime
    size: str
    ecosystem: str
    url: str


@dataclass
class SyncResult:
    """同步结果类"""

    success: bool
    message: str
    timestamp: datetime = datetime.now()
    details: Optional[Dict[str, Any]] = None
