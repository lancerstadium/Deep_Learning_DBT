# preprocess_utils.py

import os
import re
import sys
import angr
from angrutils import *
from color_cls import colors
from compile_utils import compile_module, input_file


class block_couple():
    def __init__(self, host_block: angr.Block, guest_block: angr.Block):
        self.host_block = host_block
        self.guest_block = guest_block
    
    def display(self, INST_ENABLE=False, ARCH_ENABLE=False):
        if ARCH_ENABLE:
            print(f"   {self.host_block.arch.linux_name} -> {self.guest_block.arch.linux_name}")
        if INST_ENABLE:
            print("Host instructions:")
            self.host_block.capstone.pp()
            print("Guest instructions:")            
            self.guest_block.capstone.pp()
        else:
            print(f"   {hex(self.host_block.addr)} -> {hex(self.guest_block.addr)}")

class block_similarity():
    def __init__(self, ifile: input_file):
        self.ifile = ifile
        # 加载host和guest二进制文件
        self.proj_host: angr.Project   = angr.Project(ifile.host_out  , load_options={'auto_load_libs': False})
        self.proj_guest: angr.Project  = angr.Project(ifile.guest_out , load_options={'auto_load_libs': False})
        self.preprocess_blocks: block_couple = []
    
    def analysis_bin_smilarity(self):
        self.bin_diff = self.proj_host.analyses.BinDiff(self.proj_guest)
    
    def draw_cfg(self, cfg, cfg_name):
        #调用angr-utils库可视化
        plot_cfg(cfg, cfg_name, asminst=True, remove_imports=True, remove_path_terminator=True) 

    def draw_cfgs(self):
        self.draw_cfg(self.bin_diff.cfg_a, self.ifile.cpath.replace('.c', '_host_cfg'))
        self.draw_cfg(self.bin_diff.cfg_b, self.ifile.cpath.replace('.c', '_guest_cfg'))
    
    def get_smilarity_blocks(self) -> list:
        self.analysis_bin_smilarity()
        return self.bin_diff.differing_blocks
    
    def display_preprocess_blocks(self, INST_ENABLE=False):
        print(f"Preprocess blocks:")
        for bcp in self.preprocess_blocks:
            # 如果是第一行，开启ARCH_ENABLE
            if bcp == self.preprocess_blocks[0]:
                bcp.display(INST_ENABLE, ARCH_ENABLE=True)
            else:
                bcp.display(INST_ENABLE)

    def get_preprocess_blocks(self):
        self.analysis_bin_smilarity()
        for block_cp in self.bin_diff.differing_blocks:
            host_block = self.proj_host.factory.block(block_cp[0].addr)
            guest_block = self.proj_guest.factory.block(block_cp[1].addr)
            bcp = block_couple(host_block, guest_block)
            self.preprocess_blocks.append(bcp)
        return self.preprocess_blocks

class preprocess_module():
    def __init__(self, cfile):
        self.cm = compile_module(cfile)
        self.cm.compile_test()

    def analyze_ifile(self, ifile):
        print(f"Analyze file: {ifile.cpath}")
        # 分析相似性
        bs = block_similarity(ifile)
        bs.get_preprocess_blocks()
        bs.display_preprocess_blocks()
        # 可视化    
        bs.draw_cfgs()

    def analyze(self):
        for ifile in self.cm.ifiles:
            self.analyze_ifile(ifile)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(colors.fg.YELLOW + "Usage: python preprocess_utils.py <cfile>, use `../test` as default." + colors.RESET)
        cfile = "/home/lancer/item/Deep_learning_DBT/test"
    else:
        cfile = sys.argv[1]
    
    if not os.path.isdir(cfile):
        print(f"The specified cfile '{cfile}' does not exist.")
        sys.exit(1)
    
    pm = preprocess_module(cfile)
    pm.analyze()


