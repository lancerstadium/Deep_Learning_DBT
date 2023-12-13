# preprocess_utils.py
import os
import sys
import angr
import json
from angrutils import *
from color_cls import colors
from clean_utils import delete_files_with_suffix
from compile_utils import compile_module, input_file


class block_data():
    def __init__(self, host_addr: angr.Block.addr, host_insns: str, guest_addr: angr.Block.addr, guest_insns: str):
        self.data_dict = {
            "host_addr": hex(host_addr),
            "guest_addr": hex(guest_addr),
            "host_insns": host_insns,
            "guest_insns": guest_insns
        }
    
    def display(self, INST_ENABLE=False):
        json_string = json.dumps(self.data_dict)
        print(json_string)
    
class block_couple():
    def __init__(self, host_block: angr.Block, guest_block: angr.Block):
        self.host_block = host_block
        self.guest_block = guest_block
        host_insns = ""
        for inst in host_block.capstone.insns:
            host_insns += inst.mnemonic + " " + inst.op_str + "\n"
        guest_insns = ""
        for inst in guest_block.capstone.insns:
            guest_insns += inst.mnemonic + " " + inst.op_str + "\n"
        self.b_data = block_data(host_block.addr, host_insns, guest_block.addr, guest_insns)
    
    def display(self, INST_ENABLE=False, ARCH_ENABLE=False):
        if ARCH_ENABLE:
            print(f"   Host \t<---> \tGuest")
            print(f"   {self.host_block.arch.linux_name} \t<---> \t{self.guest_block.arch.linux_name}")
        if INST_ENABLE:
            print("Host instructions:")
            self.host_block.capstone.pp()
            print("Guest instructions:")            
            self.guest_block.capstone.pp()
        else:
            print(f"   {hex(self.host_block.addr)} \t<---> \t{hex(self.guest_block.addr)}")

class block_similarity():
    def __init__(self, ifile: input_file):
        self.ifile = ifile
        # 加载host和guest二进制文件
        self.proj_host: angr.Project   = angr.Project(ifile.host_out  , load_options={'auto_load_libs': False})
        self.proj_guest: angr.Project  = angr.Project(ifile.guest_out , load_options={'auto_load_libs': False})
        self.preprocess_blocks: block_couple = []
        self.preprocess_data: list = []
        self.bin_diff: angr.analyses.BinDiff = None
    
    def analysis_bin_smilarity(self):
        self.bin_diff = self.proj_host.analyses.BinDiff(self.proj_guest)
    
    def draw_cfg(self, cfg, cfg_name):
        #调用angr-utils库可视化
        plot_cfg(cfg, cfg_name, asminst=True, remove_imports=True, remove_path_terminator=True) 

    def draw_cfgs(self):
        '''
        可视化之前，必须先分析相似性
        '''
        self.draw_cfg(self.bin_diff.cfg_a, self.ifile.cpath.replace('.c', '_host_cfg'))
        self.draw_cfg(self.bin_diff.cfg_b, self.ifile.cpath.replace('.c', '_guest_cfg'))
    
    def get_smilarity_blocks(self) -> list:
        self.analysis_bin_smilarity()
        return self.bin_diff.differing_blocks
    
    def display_preprocess_blocks(self, INST_ENABLE=False):
        '''
        显示预处理块，必须先分析相似性
        '''
        print(f"Preprocess blocks:")
        for bcp in self.preprocess_blocks:
            # 如果是第一行，开启ARCH_ENABLE
            if bcp == self.preprocess_blocks[0]:
                bcp.display(INST_ENABLE, ARCH_ENABLE=True)
            else:
                bcp.display(INST_ENABLE)

    def get_preprocess_data(self):
        self.analysis_bin_smilarity()
        for block_cp in self.bin_diff.differing_blocks:
            host_block = self.proj_host.factory.block(block_cp[0].addr)
            guest_block = self.proj_guest.factory.block(block_cp[1].addr)
            bcp = block_couple(host_block, guest_block)
            self.preprocess_blocks.append(bcp)
            self.preprocess_data.append(bcp.b_data.data_dict) # 存放每个块对的block_data
        return self.preprocess_data

class preprocess_module():
    def __init__(self, cfile, COMPILE_ENABLE=True):
        self.cm = compile_module(cfile)
        if COMPILE_ENABLE:
            self.cm.compile_test()
        self.data_lists = []    # 每个文件所含preprocess_data
        self.data_path = "./test/temp_data.json"

    def analyze_ifile(self, ifile, CFG_ENABLE=False):
        print(colors.fg.BLUE + "Analyze file: " + ifile.cpath + colors.RESET)
        # 分析相似性
        bs = block_similarity(ifile)
        data_list = bs.get_preprocess_data()
        if CFG_ENABLE:
            bs.draw_cfgs()  # 可视化
        return data_list
    
    def store_data(self, path = ""):
        path = path if path else self.data_path
        with open(path, 'w') as f:
            json.dump(self.data_lists, f)
        print(colors.fg.BLUE + "Data stored: " + path + colors.RESET)
    
    def load_data(self, path = ""):
        path = path if path else self.data_path
        with open(path, 'r') as f:
            self.data_lists = json.load(f)
        print(colors.fg.BLUE + "Data loaded: " + path + colors.RESET)

    def display_data(self):
        for data_list in self.data_lists:
            print(colors.fg.BLUE + "Data source: " + data_list['source'] + colors.RESET)
            for ts in data_list['translation']:
                print(ts)

    def analyze(self, STORE_ENABLE=False, CFG_ENABLE=False, BIN_ENABLE=False):
        print(colors.fg.BLUE + "Preprocessing..." + colors.RESET)
        for ifile in self.cm.ifiles:
            data_list = self.analyze_ifile(ifile, CFG_ENABLE)
            d_l = {
                "source": ifile.cpath,
                "translation": data_list
            }
            self.data_lists.append(d_l)
        if STORE_ENABLE:    # 存储数据
            self.store_data()
        if not BIN_ENABLE:  # 删除二进制文件
            delete_files_with_suffix( os.path.dirname(ifile.cpath), ['.out'])


if __name__ == "__main__":
    if len(sys.argv) < 2:
        cfile = "./test"
        print(colors.fg.YELLOW + "Usage: python src/preprocess.py <cfile>, use `" + cfile + "` as default." + colors.RESET)
    else:
        cfile = sys.argv[1]
    
    if not os.path.isdir(cfile):
        print(f"The specified cfile '{cfile}' does not exist.")
        sys.exit(1)
    
    pm = preprocess_module(cfile)
    pm.analyze()


