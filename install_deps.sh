#!/bin/bash
# 使用UV安装所有依赖项的脚本

set -e  # 出错时退出

# 确保uv已安装
if ! command -v uv &> /dev/null
then
    echo "uv未安装,请先安装uv: pip install uv"
    exit 1
fi

echo "===== 安装主要依赖 ====="
uv pip install -e .

echo "===== 安装开发依赖 ====="
uv pip install -e ".[dev]"

echo "===== 安装测试专用依赖 ====="
uv pip install responses pytest-playwright pytest-mock pytest-cov

echo "===== 安装类型提示依赖 ====="
uv pip install types-requests types-PyYAML types-beautifulsoup4 types-tqdm

echo "===== 安装 playwright 浏览器 ====="
playwright install chromium

echo "===== 所有依赖安装完成 =====" 