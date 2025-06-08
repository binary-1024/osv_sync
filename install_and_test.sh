#!/bin/bash
# 使用UV安装依赖并运行测试的脚本

set -e  # 出错时退出

# 确保uv已安装
if ! command -v uv &> /dev/null
then
    echo "uv未安装，请先安装uv: pip install uv"
    exit 1
fi

echo "===== 创建虚拟环境 ====="
uv venv

# 激活虚拟环境
if [ -d ".venv/bin" ]; then
    source .venv/bin/activate
else
    source .venv/Scripts/activate  # Windows
fi

echo "===== 安装依赖 ====="
uv pip install -e ".[dev]"

echo "===== 安装 playwright 浏览器 ====="
playwright install chromium

echo "===== 运行代码样式检查 ====="
echo "运行 black..."
black . --check || black .
echo "运行 isort..."
isort . --check || isort .
echo "运行 mypy..."
mypy src

echo "===== 运行测试 ====="
pytest tests -v

echo "===== 所有测试和检查已完成 =====" 