#!/bin/bash

# 激活 conda 环境
source /mnt/8t_ssd/jwh/anaconda3/etc/profile.d/conda.sh
echo $CONDA_EXE
echo $CONDA_PREFIX
echo $CONDA_PROMPT_MODIFIER
echo $CONDA_SHLVL
echo $CONDA_PYTHON_EXE
echo $CONDA_DEFAULT_ENV

export CUDA="/usr/local/cuda-12.4/bin"
export PATH="$CUDA:$PATH"

conda activate vul
conda info --envs
python --version

# 启动监控程序
echo "启动 OSV 漏洞数据库监控..."
python osv_monitor.py 


# 记得添加 cronjob 任务
# 0 2 * * * cd /完整路径/osv_vul_db_monitor && ./start_monitor.sh >> logs/cron_$(date '+\%Y-\%m-\%d_\%H-\%M-\%S').log 2>&1