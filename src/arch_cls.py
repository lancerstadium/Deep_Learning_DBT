# arch_cls.py

class arch:
    '''
    体系架构类
    '''
    def __init__(self, cc_, lc_, as_, objdump_, arch_str, cflags, qflags, opt):
        '''
        构造函数
        说明：
        :param cc_: 编译器
        :param lc_: 链接器
        :param as_: 汇编器
        :param objdump: 译码器
        :param arch_str: 架构
        :param cflags: 编译参数
        :param opt: 优化
        '''
        self.CC = cc_                       # 编译器
        self.LC = lc_                       # 链接器
        self.AS = as_                       # 汇编器
        self.OBJDUMP = objdump_             # 译码器
        self.ARCH_STR = arch_str            # 架构
        self.CFLAGS = cflags                # 编译参数
        self.OPT = opt                      # 优化选项
        self.QFLAGS = qflags                # qemu 参数
        self.QEMU = "qemu-" + arch_str      # qemu
        self.ASM = ""                       # 汇编代码文件
        self.ASM_D = ""                     # 反汇编代码文件
        self.IR = ""                        # LLVM IR代码文件

    def display_info(self):
        '''
        显示信息
        :return: None
        '''
        print(f"ARCH: {self.ARCH_STR}")
        print(f"CC: {self.CC}")
        print(f"LC: {self.LC}")
        print(f"AS: {self.AS}")
        print(f"OBJDUMP: {self.OBJDUMP}")
        print(f"ARCH_STR: {self.ARCH_STR}")
        print(f"CFLAGS: {self.CFLAGS}")
        print(f"OPT: {self.OPT}")
        print(f"QFLAGS: {self.QFLAGS}")
        print(f"QEMU: {self.QEMU}")
        print(f"ASM: {self.ASM}")
        print(f"ASM_D: {self.ASM_D}")
        print(f"IR: {self.IR}")
    