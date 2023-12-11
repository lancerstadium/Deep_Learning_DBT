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
pip install angr -i http://mirrors.aliyun.com/pypi/simple/ --trusted-host mirrors.aliyun.com
pip install angr-utils -i http://mirrors.aliyun.com/pypi/simple/ --trusted-host mirrors.aliyun.com
sudo apt-get install graphviz
dot -V
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