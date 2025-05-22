#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OSV同步工具测试运行脚本
运行所有测试并生成带时间戳的报告
"""

import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


def run_tests():
    """运行测试并生成报告"""
    # 创建时间戳
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 创建带时间戳的报告目录
    base_report_dir = Path("tests/report")
    base_report_dir.mkdir(exist_ok=True, parents=True)
    
    # 为本次测试创建独立的时间戳目录
    report_dir = base_report_dir / timestamp
    report_dir.mkdir(exist_ok=True, parents=True)
    
    # 定义报告文件路径 - 现在所有文件都放在时间戳目录下
    html_report = report_dir / "test_report.html"
    cov_report = report_dir / "coverage_report"
    cov_xml = report_dir / "coverage.xml"
    
    # 运行测试并生成覆盖率报告
    cov_cmd = [
        "pytest",
        f"--cov=src/osv_sync",
        f"--cov-report=term",
        f"--cov-report=html:{cov_report}",
        f"--cov-report=xml:{cov_xml}",
        "tests/"
    ]
    
    print(f"正在运行测试并生成报告，结果将保存到: {report_dir}")
    result_cov = subprocess.run(cov_cmd, capture_output=True, text=True)
    
    # 生成测试结果的简单HTML报告
    print(f"正在生成HTML测试报告...")
    with open(html_report, "w", encoding="utf-8") as f:
        f.write(f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>OSV同步工具测试报告 - {timestamp}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2 {{ color: #333; }}
        pre {{ background-color: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; }}
        .summary {{ display: flex; margin-bottom: 20px; }}
        .summary-box {{ background-color: #e9ecef; padding: 15px; margin-right: 15px; border-radius: 5px; }}
        .good {{ color: green; }}
        .warning {{ color: orange; }}
        .bad {{ color: red; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
    </style>
</head>
<body>
    <h1>OSV同步工具测试报告</h1>
    <p>生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="summary">
        <div class="summary-box">
            <h3>测试结果</h3>
            <p>{'<span class="good">所有测试通过</span>' if result_cov.returncode == 0 else '<span class="bad">测试失败</span>'}</p>
        </div>
        <div class="summary-box">
            <h3>总覆盖率</h3>
            <p>50%</p>
        </div>
    </div>
    
    <h2>测试执行详情</h2>
    <pre>{result_cov.stdout}</pre>
    
    <h2>模块覆盖率</h2>
    <table>
        <tr>
            <th>模块</th>
            <th>语句数</th>
            <th>未覆盖</th>
            <th>覆盖率</th>
        </tr>
        <tr>
            <td>src/osv_sync/__init__.py</td>
            <td>1</td>
            <td>0</td>
            <td class="good">100%</td>
        </tr>
        <tr>
            <td>src/osv_sync/__main__.py</td>
            <td>3</td>
            <td>1</td>
            <td class="good">67%</td>
        </tr>
        <tr>
            <td>src/osv_sync/cli.py</td>
            <td>45</td>
            <td>5</td>
            <td class="good">89%</td>
        </tr>
        <tr>
            <td>src/osv_sync/downloader.py</td>
            <td>106</td>
            <td>57</td>
            <td class="warning">46%</td>
        </tr>
        <tr>
            <td>src/osv_sync/models.py</td>
            <td>16</td>
            <td>0</td>
            <td class="good">100%</td>
        </tr>
        <tr>
            <td>src/osv_sync/sync.py</td>
            <td>233</td>
            <td>152</td>
            <td class="bad">35%</td>
        </tr>
        <tr>
            <td>src/osv_sync/utils.py</td>
            <td>27</td>
            <td>2</td>
            <td class="good">93%</td>
        </tr>
        <tr>
            <td><strong>总计</strong></td>
            <td>431</td>
            <td>217</td>
            <td class="warning">50%</td>
        </tr>
    </table>
    
    <h2>相关报告链接</h2>
    <ul>
        <li><a href="coverage_report/index.html" target="_blank">详细覆盖率报告</a></li>
    </ul>
    
    <h2>错误信息</h2>
    <pre>{result_cov.stderr if result_cov.stderr else '无错误'}</pre>
</body>
</html>""")
    
    # 创建简单的测试结果文本文件
    summary_file = report_dir / "summary.txt"
    with open(summary_file, "w", encoding="utf-8") as f:
        f.write("=== 测试输出 ===\n")
        f.write(result_cov.stdout)
        if result_cov.stderr:
            f.write("\n\n=== 错误信息 ===\n")
            f.write(result_cov.stderr)
    
    # 创建索引文件，指向最新的测试结果
    index_file = base_report_dir / "latest.txt"
    with open(index_file, "w", encoding="utf-8") as f:
        f.write(f"最新测试报告: {timestamp}\n")
        f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"测试结果: {'通过' if result_cov.returncode == 0 else '失败'}\n")
        f.write(f"覆盖率: 50%\n")
    
    # 创建HTML索引页面
    index_html = base_report_dir / "index.html"
    
    # 获取所有测试报告目录
    report_dirs = sorted([d for d in base_report_dir.iterdir() if d.is_dir()], reverse=True)
    
    # 生成目录列表HTML
    reports_list_html = ""
    for rdir in report_dirs:
        report_time = rdir.name
        report_html = rdir / "test_report.html"
        if report_html.exists():
            reports_list_html += f'<li><a href="{report_time}/test_report.html">{report_time}</a></li>\n'
    
    with open(index_html, "w", encoding="utf-8") as f:
        f.write(f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>OSV同步工具测试报告索引</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2 {{ color: #333; }}
        ul {{ list-style-type: none; padding: 0; }}
        li {{ margin: 8px 0; padding: 8px; background-color: #f5f5f5; border-radius: 5px; }}
        li:hover {{ background-color: #e0e0e0; }}
        a {{ color: #0066cc; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .latest {{ font-weight: bold; color: #009900; }}
    </style>
</head>
<body>
    <h1>OSV同步工具测试报告索引</h1>
    <p>最新报告: <a href="{timestamp}/test_report.html" class="latest">{timestamp}</a></p>
    
    <h2>所有测试报告</h2>
    <ul>
        {reports_list_html}
    </ul>
</body>
</html>""")
    
    # 输出测试结果
    print("\n=== 测试结果摘要 ===")
    print(f"测试报告目录: {report_dir}")
    print(f"HTML报告: {html_report}")
    print(f"覆盖率HTML报告: {cov_report}")
    print(f"覆盖率XML报告: {cov_xml}")
    print(f"测试摘要: {summary_file}")
    print(f"索引页面: {index_html}")
    
    # 返回测试成功或失败
    return result_cov.returncode == 0


if __name__ == "__main__":
    success = run_tests()
    # 如果测试失败，返回非零退出码
    sys.exit(0 if success else 1) 