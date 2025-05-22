# 1. 激活虚拟环境：
source .venv/bin/activate
# 2. 运行应用：
python -m osv_sync
# 3. 运行测试：
pytest
# 4. 运行类型检查：
mypy src tests
# 5. 格式化代码：
black src tests && isort src tests