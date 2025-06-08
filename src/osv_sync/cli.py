#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
命令行入口模块
"""

import argparse
import os
import sys
from pathlib import Path

from osv_sync.sync import sync_osv_data
from osv_sync.utils import load_config, setup_logging, unzip_osv_data


def main():
    """命令行主入口函数"""
    # 解析命令行参数
    parser = argparse.ArgumentParser(description="OSV 漏洞数据库同步工具")
    parser.add_argument(
        "--config",
        type=str,
        default="config.yaml",
        help="配置文件路径 (默认: config.yaml)",
    )
    args = parser.parse_args()

    try:
        # 加载配置
        config_path = args.config
        if not os.path.exists(config_path):
            print(f"错误: 配置文件 '{config_path}' 不存在")
            print(f"请确保配置文件存在或使用 --config 参数指定配置文件路径")
            sys.exit(1)

        config = load_config(config_path)

        # 设置日志
        logs_dir = Path(config["storage"]["logs_dir"])
        logs_dir.mkdir(exist_ok=True, parents=True)
        logger = setup_logging(logs_dir)

        # 确保数据目录存在
        data_dir = Path(config["storage"]["data_dir"])

        # 执行同步
        logger.info("开始同步OSV漏洞数据...")
        try:
            sync_result = sync_osv_data(config, logger, data_dir)
            logger.info("同步完成")
        except Exception as e:
            print(f"同步过程中发生错误: {e}")
            sys.exit(1)

        # 解压缩文件
        if sync_result:
            try:
                unzip_path = data_dir / Path("all.zip")
                unzip_osv_data(unzip_path, data_dir)
            except Exception as e:
                print(f"解压缩文件失败: {e}")
                sys.exit(1)
            logger.info("解压缩文件完成")
        else:
            logger.info("同步失败, 不进行解压缩")

    except KeyError as e:
        print(f"配置文件格式错误: 缺少必要的配置项 {e}")
        sys.exit(1)
    except Exception as e:
        print(f"同步过程中发生错误: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
