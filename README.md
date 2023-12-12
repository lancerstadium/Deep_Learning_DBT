# Experiments 实验

    本文进行了如下实验

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

- Install

```
sudo apt install clang-15 llvm-15
sudo apt-get install gcc-aarch64-linux-gnu
pip install angr
pip install angr -i https://pypi.tuna.tsinghua.edu.cn/simple
pip install angr-utils -i https://pypi.tuna.tsinghua.edu.cn/simple
sudo apt-get install graphviz
dot -V
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple transformers
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple torch
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple accelerate -U

pip install -i https://pypi.tuna.tsinghua.edu.cn/simple tranformers==4.30.1
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple torch=2.0.0

pip install --upgrade transformers==4.30.1 
pip install --upgrade torch==2.0.0
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