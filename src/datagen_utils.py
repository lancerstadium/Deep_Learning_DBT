# datagen_tuils.py
import os
from color_cls import colors
from scan_utils import init_bin_list
from compile_utils import *
from clean_utils import delete_files_with_suffix
from tqdm import tqdm


class datagen_module():
    def __init__(self):
        self.bin_list = init_bin_list()
        self.host_od_dir = os.path.join(origin_data_dir, host.ARCH_STR)
        self.guest_od_dir = os.path.join(origin_data_dir, guest.ARCH_STR)
        if not os.path.exists(self.host_od_dir) :
            cmd = f"mkdir {self.host_od_dir}"
            os.system(cmd)
        if not os.path.exists(self.guest_od_dir) :
            cmd = f"mkdir {self.guest_od_dir}"
            os.system(cmd)
    
    def get_host_bin(self, bin_file):
        return os.path.join(host_bin_dir, bin_file)
    
    def get_guest_bin(self, bin_file):
        return os.path.join(guest_bin_dir, bin_file)
    
    def get_host_data_file(self, bin_file):
        return os.path.join(host_bin_dir, bin_file + '_cfg.json')
    
    def get_guest_data_file(self, bin_file):
        return os.path.join(guest_bin_dir, bin_file + '_cfg.json')
    
    def extract_cfg(self):
        # print(colors.fg.BLUE + "Extract start ..." + colors.RESET)
        for bin_file in tqdm(self.bin_list, desc=colors.fg.BLUE + "Extract cfg `json` " + colors.RESET, colour='#6DCBFA'):
            host_bin = self.get_host_bin(bin_file)
            guest_bin = self.get_guest_bin(bin_file)
            cmd = f"{bin2ml_path} extract --fpath {host_bin} --output-dir {self.host_od_dir} --mode cfg 2> {origin_data_log_file}"
            os.system(cmd)
            cmd = f"{bin2ml_path} extract --fpath {guest_bin} --output-dir {self.guest_od_dir} --mode cfg 2> {origin_data_log_file}"
            os.system(cmd)
        # print(colors.fg.BLUE + "Extract end ..." + colors.RESET)

    def gen_origin_data(self):
        print(colors.fg.BLUE + "Generate `.json` origin data ..." + colors.RESET)
        self.extract_cfg()

    def del_all_origin_data(self):
        delete_files_with_suffix(self.guest_od_dir, ['_cfg.json'])
        delete_files_with_suffix(self.host_od_dir, ['_cfg.json'])



if __name__ == "__main__":
    dm = datagen_module()
    dm.gen_origin_data()