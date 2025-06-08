#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
测试主入口模块
"""

import unittest
from unittest import mock

from osv_sync import __main__


class TestMain(unittest.TestCase):
    """主入口模块测试用例"""

    def test_main_module_exists(self):
        """测试主模块存在"""
        # 简单验证模块存在
        self.assertTrue(hasattr(__main__, "__file__"))


if __name__ == "__main__":
    unittest.main() 