#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
测试工具模块
"""

import logging
import os
import tempfile
import zipfile
from pathlib import Path
from unittest import TestCase, mock

import yaml

from osv_sync.utils import load_config, setup_logging, unzip_osv_data


class TestUtils(TestCase):
    """测试工具函数"""

    def test_setup_logging(self):
        """测试日志设置"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            logger = setup_logging(tmp_dir)

            # 验证返回的是日志对象
            self.assertIsInstance(logger, logging.Logger)

            # 验证日志文件已创建
            log_files = list(Path(tmp_dir).glob("*.log"))
            self.assertGreaterEqual(len(log_files), 1)

    def test_load_config(self):
        """测试配置加载"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_config_path = os.path.join(tmp_dir, "test_config.yaml")

            # 创建测试配置
            test_config = {
                "source": {
                    "base_url": "https://test.com",
                },
                "storage": {
                    "data_dir": "test_data",
                    "logs_dir": "test_logs",
                },
            }

            # 写入测试配置
            with open(tmp_config_path, "w", encoding="utf-8") as f:
                yaml.dump(test_config, f)

            # 模拟当前工作目录
            with mock.patch("os.getcwd", return_value=tmp_dir):
                config = load_config("test_config.yaml")

                # 验证配置是否正确加载
                self.assertEqual(config["source"]["base_url"], "https://test.com")
                self.assertEqual(config["storage"]["data_dir"], "test_data")
                self.assertEqual(config["storage"]["logs_dir"], "test_logs")

    def test_unzip_osv_data(self):
        """测试OSV数据解压缩功能"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_dir_path = Path(tmp_dir)
            zip_path = tmp_dir_path / "test.zip"
            data_dir = tmp_dir_path / "data"
            
            # 创建测试zip文件
            test_content = b"test content"
            with zipfile.ZipFile(zip_path, "w") as zip_ref:
                zip_ref.writestr("test_file.txt", test_content)
            
            # 测试解压缩功能
            unzip_osv_data(zip_path, data_dir)
            
            # 验证解压目录是否创建
            all_vuln_dir = data_dir / "all_vuln"
            self.assertTrue(all_vuln_dir.exists())
            
            # 验证文件是否正确解压
            extracted_file = all_vuln_dir / "test_file.txt"
            self.assertTrue(extracted_file.exists())
            
            # 验证文件内容
            with open(extracted_file, "rb") as f:
                content = f.read()
                self.assertEqual(content, test_content)
                
    def test_unzip_osv_data_bad_zip(self):
        """测试处理损坏的zip文件"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_dir_path = Path(tmp_dir)
            zip_path = tmp_dir_path / "bad.zip"
            data_dir = tmp_dir_path / "data"
            
            # 创建一个无效的zip文件
            with open(zip_path, "wb") as f:
                f.write(b"not a valid zip file")
            
            # 测试是否正确抛出异常
            with self.assertRaises(zipfile.BadZipFile):
                unzip_osv_data(zip_path, data_dir)
