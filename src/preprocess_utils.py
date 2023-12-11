# preprocess_utils.py

import os
import re
import sys
import angr
from angrutils import *
from color_cls import colors
from compile_utils import compile_module


class preprocess_module():
    def __init__(self, cfile):
        self.cm = compile_module(cfile)
        self.cm.compile_test()

    def plot_cfg(self, cfg, cfg_name):
        #调用angr-utils库可视化
        plot_cfg(cfg, cfg_name, asminst=True, remove_imports=True, remove_path_terminator=True)  

    # 通过simhash_distance来判断基本块的相似度
    def simhash_distance(self, block1, block2):
        # 编写simhash算法
        close_rate = 0.0
        return close_rate


    def analyze_ifile(self, ifile):
        print(f"Analyze file: {ifile.cpath}")
        # 加载host和guest二进制文件
        proj_host   = angr.Project(ifile.host_out  , load_options={'auto_load_libs': False})
        proj_guest  = angr.Project(ifile.guest_out , load_options={'auto_load_libs': False})

        # 分析host和guest二进制文件
        cfg_host    = proj_host.analyses.CFGFast()
        cfg_guest   = proj_guest.analyses.CFGFast()

        state_host  = proj_host.factory.entry_state()
        state_guest = proj_guest.factory.entry_state()

        # self.plot_cfg(cfg_host, ifile.cpath.replace('.c', '_host_cfg'))
        # self.plot_cfg(cfg_guest, ifile.cpath.replace('.c', '_guest_cfg'))
        

        # # 遍历x86_64二进制文件的基本块
        # for node_host in cfg_host.graph.nodes():
        #     block_host = cfg_host.model.get_any_node(node_host.addr)
        #     # 遍历aarch64二进制文件的基本块
        #     for node_guest in cfg_guest.graph.nodes():
        #         block_guest = cfg_guest.model.get_any_node(node_guest.addr)
        #         # 比较基本块指令序列，如果相似则收集其代码
        #         if self.simhash_distance(block_host, block_guest) < 5:  # 通过simhash_distance来判断基本块的相似度
        #             code_host = proj_host.factory.block(block_host.addr, block_host.size).capstone.pp()
        #             code_guest = proj_guest.factory.block(block_guest.addr, block_guest.size).capstone.pp()
        #             print(f"Similar basic blocks found at addresses 0x{block_host.addr:x} (x86_64) and 0x{block_guest.addr:x} (aarch64)")
        #             print("x86_64 code:", code_host)
        #             print("aarch64 code:", code_guest)
                
        # 获取第一个block_host
        addr_host = next(iter(cfg_host.kb.functions))
        addr_guest = next(iter(cfg_guest.kb.functions))

        state_host.ip = addr_host
        state_guest.ip = addr_guest

        # 获取要比对的两个基本块
        block_host = proj_host.factory.block(addr_host)
        block_guest = proj_guest.factory.block(addr_guest)

        block_host.capstone.pp()
        block_guest.capstone.pp()

        block_diffs = angr.analyses.bindiff.FunctionDiff.block_similarity(block_host, block_guest)
        print(f"{block_diffs}")

        # # 比较基本块指令序列，如果相似则收集其代码
        # if self.simhash_distance(block_host, block_guest) < 5:  # 通过simhash_distance来判断基本块的相似度
        #     code_host = proj_host.factory.block(block_host.addr, block_host.size).capstone.pp()
        #     code_guest = proj_guest.factory.block(block_guest.addr, block_guest.size).capstone.pp()
        #     print(f"Similar basic blocks found at addresses 0x{block_host.addr:x} (x86_64) and 0x{block_guest.addr:x} (aarch64)")
        #     print("x86_64 code:", code_host)
        #     print("aarch64 code:", code_guest)

        simgr_host = proj_host.factory.simgr(state_host)
        simgr_guest = proj_guest.factory.simgr(state_guest)

        simgr_host.active
        simgr_guest.active

        simgr_host.step()
        simgr_guest.step()

        


    def analyze(self):
        for ifile in self.cm.ifiles:
            # 先只分析第一个文件
            if ifile.cpath == self.cm.ifiles[0].cpath:
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


