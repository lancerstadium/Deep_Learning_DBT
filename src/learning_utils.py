# learning_utils.py

import os
import sys
import angr
from color_cls import colors
from transformers import pipeline
from preprocess_utils import preprocess_module


class learning_module:
    def __init__(self, cfile):
        self.pm = preprocess_module(cfile)
        self.pm.analyze(STORE_ENABLE=False)
        self.data = []
        self.source = "aarch64"
        self.target = "x86_64"
    
    def display_origin_data(self):
        for data_list in self.pm.data_lists:
            print(colors.fg.BLUE + "Data source: " + data_list['source'] + colors.RESET)
            for ts in data_list['translation']:
                print(ts)
    
    def display_data(self):
        for ts in self.data:
            print(ts)

    def extract_data(self):
        for data_list in self.pm.data_lists:
            for ts in data_list['translation']:
                temp = {
                    self.source : ts["guest_insns"],
                    self.target : ts["host_insns"]
                }
                self.data.append(temp)
    
    def store_data(self, path="./test/temp_data.json"):
        self.pm.store_data(path)
    
    def load_data(self, path="./test/temp_data.json"):
        self.pm.load_data(path)
    
    def learning_test(self):
        self.extract_data()
        self.display_data()
        # classifier = pipeline("sentiment-analysis",
        #               model="IDEA-CCNL/Erlangshen-Roberta-110M-Sentiment")
        # result = classifier("今天心情很坏")
        # print(result)


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
    lm.learning_test()
