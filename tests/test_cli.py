#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
测试命令行接口模块
"""

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

from osv_sync.cli import main


class TestCLI(unittest.TestCase):
    """命令行接口测试用例"""

    @mock.patch("osv_sync.cli.load_config")
    @mock.patch("osv_sync.cli.setup_logging")
    @mock.patch("osv_sync.cli.sync_osv_data")
    @mock.patch("osv_sync.cli.unzip_osv_data")
    @mock.patch("sys.argv", ["osv-sync"])
    def test_main_default_config(self, mock_unzip, mock_sync, mock_logger, mock_load_config):
        """测试使用默认配置的主函数"""
        # 设置模拟返回值
        mock_logger.return_value = mock.MagicMock()
        mock_load_config.return_value = {
            "storage": {
                "data_dir": "data",
                "logs_dir": "logs",
            },
            "recording": {
                "file_path": "logs/sync_history.csv",
            },
        }
        
        # 模拟文件存在
        with mock.patch("os.path.exists", return_value=True):
            # 执行主函数
            main()
            
        # 验证调用
        mock_load_config.assert_called_once_with("config.yaml")
        mock_logger.assert_called_once()
        mock_sync.assert_called_once()
        mock_unzip.assert_called_once()

    @mock.patch("osv_sync.cli.load_config")
    @mock.patch("sys.argv", ["osv-sync", "--config", "custom_config.yaml"])
    @mock.patch("sys.exit")
    def test_main_custom_config(self, mock_exit, mock_load_config):
        """测试使用自定义配置的主函数"""
        # 设置模拟返回值
        mock_load_config.side_effect = KeyError("missing_key")
        
        # 模拟文件存在
        with mock.patch("os.path.exists", return_value=True):
            # 执行主函数
            main()
            
        # 验证调用
        mock_load_config.assert_called_once_with("custom_config.yaml")
        mock_exit.assert_called_once_with(1)

    @mock.patch("sys.argv", ["osv-sync", "--config", "nonexistent.yaml"])
    @mock.patch("sys.exit")
    def test_main_nonexistent_config(self, mock_exit):
        """测试不存在的配置文件"""
        # 模拟文件不存在
        with mock.patch("os.path.exists", return_value=False):
            # 执行主函数
            main()
            
        # 验证系统退出被调用
        mock_exit.assert_any_call(1)

    @mock.patch("osv_sync.cli.load_config")
    @mock.patch("osv_sync.cli.setup_logging")
    @mock.patch("osv_sync.cli.sync_osv_data")
    @mock.patch("sys.argv", ["osv-sync"])
    @mock.patch("sys.exit")
    def test_main_sync_exception(self, mock_exit, mock_sync, mock_logger, mock_load_config):
        """测试同步过程中的异常处理"""
        # 设置模拟返回值
        mock_logger.return_value = mock.MagicMock()
        mock_load_config.return_value = {
            "storage": {
                "data_dir": "data",
                "logs_dir": "logs",
            },
            "recording": {
                "file_path": "logs/sync_history.csv",
            },
        }
        mock_sync.side_effect = Exception("同步错误")
        
        # 模拟文件存在
        with mock.patch("os.path.exists", return_value=True):
            # 执行主函数
            main()
            
        # 验证系统退出被调用
        mock_exit.assert_any_call(1)


if __name__ == "__main__":
    unittest.main() 