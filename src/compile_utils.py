# compile_utils.py
import os
import sys
import platform
from config import *
from color_cls import colors

class input_file():
    
    def __init__(self, cpath):
        self.cpath      = cpath
        self.guest_out  = ""
        self.host_out   = ""
    
    def reset(self):
        '''
        重置实例属性
        '''
        self.cpath      = ""
        self.guest_out  = ""
        self.host_out   = ""
    
    def is_empty(self):
        '''
        判断是否为空
        '''
        return self.guest_out == "" or self.host_out == ""
    

class compile_module():
    '''
    编译模块: step 1
    '''
    def __init__(self, cfile):
        # 设置编译文件目录
        self.cfile = cfile
        # 获取主机架构
        self.host_arch_str = platform.machine()
        # ifiles: 存储文件列表
        self.ifiles = []
        self.ifile = input_file("")
        self.QEMU_ENABLE = False
        self.COREUTILS_ENABLE = False

    def display(self):
        '''
        显示信息
        :return: None
        '''
        print(f"cfile: {self.cfile}")
        print(f"host_arch_str: {self.host_arch_str}")
        for ifile in self.Ifiles:
            ifile.display()
    
    def compile_out(self, arch, file_path):
        output_out = file_path.replace('.c', '_' + arch.ARCH_STR + '_bin').replace('.cpp', '_' + arch.ARCH_STR + '_bin').replace('.cc', '_' + arch.ARCH_STR + '_bin')
        cmd = f"{arch.CC} {arch.CFLAGS} {arch.OPT} -o {output_out} {file_path} 2> .tmp"
        os.system(cmd)
        return output_out
    
    def qemu_out(self, arch, output_out):
        if arch.ARCH_STR == self.host_arch_str:
            cmd = f"{output_out} 2> .tmp"
            os.system(cmd)
        else:
            cmd = f"{arch.QEMU} {arch.QFLAGS} {output_out} 2> .tmp"
            os.system(cmd)
    
    def compile_with_arch(self, host, guest):
        # 遍历指定目录
        for root, dirs, files in os.walk(self.cfile):
            for file in files: 
                # 判断文件类型
                if file.endswith(('.c', '.cpp', '.cc')):
                    file_path = os.path.join(root, file)
                    ifile = input_file(file_path)
                    # 1. 编译文件
                    ifile.host_out = self.compile_out(host, file_path)
                    ifile.guest_out = self.compile_out(guest, file_path)
                    # 2. QEMU 运行测试
                    if self.QEMU_ENABLE:
                        self.qemu_out(host, ifile.host_out)
                        self.qemu_out(guest, ifile.guest_out)
                    # 3. 生成文件加入ifile
                    if not ifile.is_empty():
                        self.ifiles.append(ifile)
                    

    def compile_test(self):
        print(colors.fg.BLUE + "Compiling..." + colors.RESET)
        self.compile_with_arch(host, guest)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        cfile = abs_item_dir + "test"
        print(colors.fg.YELLOW + "Usage: python src/compile_utils.py <cfile>, use `" + cfile + "` as default." + colors.RESET)
    else:
        cfile = sys.argv[1]
    
    if not os.path.isdir(cfile):
        print(f"The specified cfile '{cfile}' does not exist.")
        sys.exit(1)
    
    cm = compile_module(cfile)
    cm.compile_test()
