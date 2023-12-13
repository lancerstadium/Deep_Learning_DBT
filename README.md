# Experiments 实验

## Environment 实验环境

OS: Linux Ubuntu 22.04 LTS
Guest ISA: aarch64
Host ISA: x86_64
Compiler: LLVM-15.0
Symbol execution: Angr
DBT: Qemu-4.1.0
Benchmark: Spec2006


- check host ISA:
```
uname -m
```

- Miniconda Install

url: https://docs.conda.io/projects/miniconda/en/latest/

```
mkdir -p ~/miniconda3
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O ~/miniconda3/miniconda.sh
bash ~/miniconda3/miniconda.sh -b -u -p ~/miniconda3
rm -rf ~/miniconda3/miniconda.sh
```

安装后，初始化新安装的 Miniconda。以下命令针对 bash 和 zsh shell 进行初始化：
```
~/miniconda3/bin/conda init bash
~/miniconda3/bin/conda init zsh
```

- Package Install

安装：
```
sudo apt install clang-15 llvm-15
sudo apt-get install gcc-aarch64-linux-gnu graphviz

# global
pip install angr
pip install angr-utils
pip install transformers
pip install torch
pip install accelerate -U
pip install sentencepiece
pip install datasets

# zh
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple angr
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple angr-utils
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple transformers
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple torch
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple accelerate -U

```

管理：
```
conda list --export > requirements.txt
```


## Module 模块

1. Data Collection Module

> Guest Host -> CFG 图
> Symbol 需要的数据

2. Data Process Module

> 一对
> "hello" -> "你好"


3. Transformer Module




4. Symbolic Execution Module

> Angr