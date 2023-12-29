from arch_cls import arch

## ======== Compile Module 全局变量 ======== ##

# 二进制程序目录
abs_item_dir = '/home/lancer/item/Deep_Learning_DBT/'
guest_bin_dir = abs_item_dir + 'submodule/Toolpacks/aarch64_arm64'  
host_bin_dir  = abs_item_dir + 'submodule/Toolpacks/x86_64'  
bin2ml_path = abs_item_dir + "submodule/bin2ml/target/release/bin2ml"
origin_data_dir = abs_item_dir + 'benchmark/origin_data'
origin_data_log_file = abs_item_dir + 'odgen.log'

# 配置信息
CFLAG_STR = "-g -DSPEC_CPU -std=c++11  -DNDEBUG -DPERL_CORE -DSPEC_CPU_LINUX -L /usr/aarch-linux-gnu -std=gnu89"
OPT_HOST = "-O2"
OPT_GUEST = "-O2"

# Host ISA: 创建x86_64架构实例
host = arch(
    "clang-15", 
    "lld-15", 
    "as", 
    "objdump", 
    "x86_64", 
    CFLAG_STR,
    "",
    OPT_HOST
)
# Guest ISA: 创建arm64架构实例
guest = arch(
    "clang-15 -target aarch64-linux-gnu",
    "aarch64-linux-gnu-ld", 
    "aarch64-linux-gnu-as", 
    "aarch64-linux-gnu-objdump", 
    "aarch64", 
    CFLAG_STR,
    "-L /usr/aarch64-linux-gnu/",
    OPT_GUEST
)