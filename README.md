# Experiments 实验

## Environment 实验环境

OS: Linux Ubuntu 22.04 LTS
Guest ISA: aarch64
Host ISA: x86_64
Compiler: LLVM-15.0
Symbol execution: Angr
DBT: Qemu-4.1.0
Benchmark: Spec2006, coreutils-8.29


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

conda create -n dl_dbt python=3.12
```

- Rust Install
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

- Package Install

安装：
```
sudo apt install clang-15 llvm-15
sudo apt-get install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu graphviz

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
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple sentencepiece
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple datasets


conda activate dl_dbt
conda install angr
conda install angr-utils
conda install transformers
conda install torch
conda install accelerate -U
conda install sentencepiece
conda install datasets
conda install fasttest

```

- Submodule Install


```
git clone https://github.com/radareorg/radare2
radare2/sys/install.sh
cd submodule
git submodule add https://github.com/br0kej/bin2ml.git

```

- Benchmark Install & Use


```
cd submodule
git submodule add https://github.com/Azathothas/Toolpacks.git
```


- Miniconda Manage
```
conda create -n dl_dbt python=3.10
conda activate dl_dbt 
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