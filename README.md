# OSV 漏洞数据库监控

一个用于监控和同步 [OSV 漏洞数据库](https://storage.googleapis.com/osv-vulnerabilities) 的工具。

## 功能

- 每日自动同步 OSV 漏洞数据库
- 支持增量更新，只下载变化的数据
- 支持多生态系统的漏洞数据同步

## 使用方法

1. 安装依赖：`pip install -r requirements.txt`
2. 配置同步参数（可选）：编辑 `config.yaml`
3. 运行同步：`python osv_monitor.py`
4. 设置定时任务以实现每日自动同步

## 目录结构

- `data/`: 存储下载的漏洞数据
- `logs/`: 存储运行日志
- `osv_monitor.py`: 主监控脚本
- `requirements.txt`: 项目依赖
- `config.yaml`: 配置文件 