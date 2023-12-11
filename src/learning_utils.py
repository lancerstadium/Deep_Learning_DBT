# learning_utils.py

import os
import sys
import angr
from color_cls import colors
from preprocess_utils import preprocess_module


class learning_module:
    def __init__(self, cfile):
        self.pm = preprocess_module(cfile)
        self.pm.analyze()
    
    def display_data(self):
        index = 1
        for data_list in self.pm.data_lists:
            print(f"Data list: file{index}")
            for data in data_list:
                data.display(INST_ENABLE=True)
            index = index + 1
            


if __name__ == "__main__":
    if len(sys.argv) < 2:
        cfile = "./test"
        print(colors.fg.YELLOW + "Usage: python src/learning_utils.py <cfile>, use `" + cfile + "` as default." + colors.RESET)
    else:
        cfile = sys.argv[1]
    
    if not os.path.isdir(cfile):
        print(f"The specified cfile '{cfile}' does not exist.")
        sys.exit(1)
    
    lm = learning_module(cfile)
    lm.display_data()

