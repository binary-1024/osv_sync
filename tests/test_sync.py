#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OSV同步功能测试模块
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import responses
from playwright.sync_api import sync_playwright

from osv_sync.downloader import Downloader
from osv_sync.sync import (
    check_all_zip_update,
    check_validation,
    log_file_operation,
    sync_osv_data,
)


class TestOSVSync(unittest.TestCase):
    """OSV同步功能测试用例"""

    def setUp(self):
        """设置测试环境"""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config = {
            "source": {
                "base_url": "https://storage.googleapis.com/osv-vulnerabilities",
                "index_url": "https://storage.googleapis.com/osv-vulnerabilities/index.html",
                "all_zip_url": "https://storage.googleapis.com/osv-vulnerabilities/all.zip",
            },
            "storage": {
                "data_dir": os.path.join(self.temp_dir.name, "data"),
                "logs_dir": os.path.join(self.temp_dir.name, "logs"),
            },
            "recording": {
                "file_path": os.path.join(
                    self.temp_dir.name, "logs", "sync_history.csv"
                ),
            },
            "sync": {
                "timeout": 3000,
                "retry_attempts": 3,
            },
            "browser": {
                "browser_type": "chromium",
                "headless": True,
                "timeout": 30000,
                "viewport": {"width": 1280, "height": 800},
                "options": {"args": ["--disable-gpu", "--no-sandbox"]},
            },
        }

        # 创建日志模拟对象
        self.logger_mock = mock.MagicMock()
        self.logger_mock.info = mock.MagicMock()
        self.logger_mock.error = mock.MagicMock()
        self.logger_mock.warning = mock.MagicMock()

    def tearDown(self):
        """清理测试环境"""
        self.temp_dir.cleanup()

    @responses.activate
    def test_downloader(self):
        """测试下载器功能"""
        # 设置模拟响应
        responses.add(
            responses.GET,
            "https://example.com/test.json",
            json={"test": "data"},
            status=200,
            content_type="application/json",
        )

        # 创建测试文件路径
        test_file = Path(self.config["storage"]["data_dir"]) / "test.json"

        # 初始化下载器
        downloader = Downloader(self.config, self.logger_mock)

        # 测试下载
        result = downloader.download_file(
            url="https://example.com/test.json",
            dest_path=test_file,
        )

        # 检查结果
        self.assertTrue(result)
        self.assertTrue(test_file.exists())

        # 验证日志调用
        self.logger_mock.info.assert_called()

    def test_check_validation_valid_json(self):
        """测试有效JSON文件验证"""
        # 创建测试JSON文件
        test_dir = Path(self.temp_dir.name)
        test_file = test_dir / "valid.json"
        with open(test_file, "w") as f:
            f.write('{"test": "data"}')

        # 测试验证
        try:
            check_validation(test_file, self.logger_mock)
            validation_passed = True
        except Exception:
            validation_passed = False

        self.assertTrue(validation_passed)

    def test_check_validation_invalid_json(self):
        """测试无效JSON文件验证"""
        # 创建无效测试JSON文件
        test_dir = Path(self.temp_dir.name)
        test_file = test_dir / "invalid.json"
        with open(test_file, "w") as f:
            f.write('{"test": invalid}')  # 无效JSON

        # 测试验证
        with self.assertRaises(Exception):
            check_validation(test_file, self.logger_mock)

        # 验证文件已被删除
        self.assertFalse(test_file.exists())

    def test_log_file_operation(self):
        """测试日志文件操作"""
        from datetime import datetime

        # 设置
        logs_dir = Path(self.config["storage"]["logs_dir"])
        logs_dir.mkdir(exist_ok=True, parents=True)

        # 测试日志记录
        test_time = datetime.now()
        log_file_operation(test_time, self.config, self.logger_mock)

        # 验证日志文件已创建
        log_file = Path(self.config["recording"]["file_path"])
        self.assertTrue(log_file.exists())

        # 验证内容
        with open(log_file, "r") as f:
            content = f.read()
            self.assertIn("date,file_rela_path,last_modified_time", content)
            self.assertIn("data/all.zip", content)

    def test_check_all_zip_update_no_log(self):
        """测试无日志时的更新检查"""
        from datetime import datetime

        # 无日志文件时测试
        result = check_all_zip_update(datetime.now(), self.config)

        # 应返回True表示需要更新
        self.assertTrue(result)

    @mock.patch("osv_sync.sync.with_playwright")
    def test_sync_osv_data_no_update(self, mock_playwright):
        """测试不需要更新时的同步"""
        from datetime import datetime

        # 设置模拟
        mock_playwright.return_value = (
            ["ecosystem1", "ecosystem2"],
            {
                "all.zip": {
                    "name": "all.zip",
                    "last_modified": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
            },
        )

        # 创建日志文件表示不需要更新
        logs_dir = Path(self.config["recording"]["file_path"]).parent
        logs_dir.mkdir(exist_ok=True, parents=True)

        # 设置不需要更新
        with mock.patch("osv_sync.sync.check_all_zip_update", return_value=False):
            # 运行同步
            data_dir = Path(self.config["storage"]["data_dir"])
            sync_osv_data(self.config, self.logger_mock, data_dir)

        # 验证日志调用包含完成信息
        self.logger_mock.info.assert_any_call("[+] 同步 OSV 数据完成")


if __name__ == "__main__":
    unittest.main()
