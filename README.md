# OSV 同步工具

一个用于同步 [OSV (Open Source Vulnerabilities)](https://osv.dev/) 漏洞数据库的工具。

## 功能特点

- 自动同步 OSV 漏洞数据库
- 支持增量同步，避免重复下载
- 提供命令行界面
- 日志记录和错误处理
- 文件完整性验证

## 安装

确保已安装 UV（<https://github.com/astral-sh/uv>）。

```bash
# 创建并激活虚拟环境
uv venv
source .venv/bin/activate  # Linux/macOS
# 或者
# .venv\Scripts\activate  # Windows

# 安装依赖
uv pip install -e .
```

## 快速开始

1. 创建配置文件 `config.yaml`（可参考项目根目录的示例配置文件）
2. 运行同步命令：

```bash
uv pip install -e ".[dev]"
```

## 配置说明

配置文件采用 YAML 格式，主要包含以下部分：

```yaml
source:
  base_url: "https://storage.googleapis.com/osv-vulnerabilities"
  index_url: "https://storage.googleapis.com/osv-vulnerabilities/index.html"
  all_zip_url: "https://storage.googleapis.com/osv-vulnerabilities/all.zip"

storage:
  data_dir: "data"  # 数据存储目录
  logs_dir: "logs"  # 日志目录

recording:
  file_path: "logs/sync_history.csv"  # 同步记录文件

sync:
  timeout: 3000  # 下载超时时间（毫秒）
  retry_attempts: 3  # 重试次数

browser:
  browser_type: "chromium"  # 浏览器类型：firefox, webkit, chromium
  headless: true  # 是否无头模式
  timeout: 30000  # 浏览器超时时间（毫秒）
  viewport:
    width: 1280
    height: 800
  options:
    args: ["--disable-gpu", "--no-sandbox"]
```

## 项目结构

```
osv_sync/
├── config.yaml          # 配置文件
├── src/
│   └── osv_sync/        # 源代码
│       ├── __init__.py
│       ├── __main__.py  # 入口点
│       ├── cli.py       # 命令行接口
│       ├── models.py    # 数据模型
│       ├── sync.py      # 同步逻辑
│       ├── downloader.py # 下载器
│       └── utils.py     # 工具函数
├── tests/               # 测试用例
│   └── test_sync.py
├── data/                # 数据目录
└── logs/                # 日志目录
```

## 开发

### 安装开发依赖

```bash
uv pip install -e ".[dev]"
```

### 自动安装并测试

可以使用项目根目录下的脚本一键安装依赖并运行测试：

```bash
chmod +x install_and_test.sh
./install_and_test.sh
```

### 运行测试

```bash
black src && python -m osv_sync
```
太棒了！我们已经完成了基于 uv 管理的 Python 项目的创建。以下是项目的结构和功能：

### 代码风格检查

```bash
black .
isort .
mypy src
```

## 使用方式

1. 激活虚拟环境：`source .venv/bin/activate`
2. 运行应用：`python -m osv_sync`
3. 运行测试：`pytest`
4. 运行类型检查：`mypy src tests`
5. 格式化代码：`black src tests && isort src tests`

## 许可证

MIT

声明: 该项目中部分代码由 Cursor + claude-3.7-sonnet 生成

# 安装所有依赖
./install_deps.sh

# 或者一键安装依赖并运行测试
./install_and_test.sh
