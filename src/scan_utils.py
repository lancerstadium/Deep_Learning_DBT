# scan_utils.py

import os
from color_cls import colors
from config import guest_bin_dir, host_bin_dir

def init_bin_list():
    print(colors.fg.BLUE + 'Scanning ...' + colors.RESET)
    guest_bin_list = os.listdir(guest_bin_dir)
    host_bin_list = os.listdir(host_bin_dir)
    print('Guest dir: ' + str(guest_bin_dir) + 
        '\nHost  dir: ' + str(host_bin_dir))
    # 去除带有后缀的文件名
    guest_bin_set = {file for file in guest_bin_list if not os.path.splitext(file)[1]}
    host_bin_set = {file for file in host_bin_list if not os.path.splitext(file)[1]}
    guest_bin_size = len(guest_bin_set)
    host_bin_size = len(host_bin_set)
    bin_list = list(sorted(guest_bin_set & host_bin_set))
    bin_size = len(bin_list)
    print('Guest: ' + str(guest_bin_size) + 
          ' Host: ' + str(host_bin_size) +
          colors.fg.GREEN + ' Total: '+ str(bin_size) + ' same binaries.' + colors.RESET)
    # print(bin_list)
    return bin_list

if __name__ == "__main__":
    init_bin_list()