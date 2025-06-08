#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
测试数据模型模块
"""

import unittest
from datetime import datetime

from osv_sync.models import FileInfo, SyncResult


class TestModels(unittest.TestCase):
    """数据模型测试用例"""

    def test_file_info(self):
        """测试FileInfo数据类"""
        # 创建测试数据
        test_date = datetime.now()
        file_info = FileInfo(
            name="test.zip",
            last_modified=test_date,
            size="1024",
            ecosystem="npm",
            url="https://example.com/test.zip",
        )

        # 验证属性
        self.assertEqual(file_info.name, "test.zip")
        self.assertEqual(file_info.last_modified, test_date)
        self.assertEqual(file_info.size, "1024")
        self.assertEqual(file_info.ecosystem, "npm")
        self.assertEqual(file_info.url, "https://example.com/test.zip")

    def test_sync_result_default_values(self):
        """测试SyncResult默认值"""
        # 使用最小参数创建
        result = SyncResult(success=True, message="测试成功")

        # 验证必需属性
        self.assertTrue(result.success)
        self.assertEqual(result.message, "测试成功")
        
        # 验证默认属性
        self.assertIsNone(result.details)
        self.assertIsInstance(result.timestamp, datetime)

    def test_sync_result_all_values(self):
        """测试SyncResult所有值设置"""
        # 创建测试数据
        test_date = datetime.now()
        test_details = {"files": 10, "errors": 0}
        
        result = SyncResult(
            success=False,
            message="测试失败",
            timestamp=test_date,
            details=test_details
        )

        # 验证属性
        self.assertFalse(result.success)
        self.assertEqual(result.message, "测试失败")
        self.assertEqual(result.timestamp, test_date)
        self.assertEqual(result.details, test_details)


if __name__ == "__main__":
    unittest.main() 