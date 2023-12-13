# learning_utils.py
import os
import sys

from color_cls import colors
from config import host, guest
from preprocess_utils import preprocess_module

# from torch.utils.data import Dataset, random_split
from datasets import Dataset
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM, Seq2SeqTrainingArguments, Seq2SeqTrainer, DataCollatorForSeq2Seq


class learning_module:
    def __init__(self, cfile):
        self.JSON_PATH = "./test/temp_data.json"
        self.MODEL_DIR = "./model"
        self.source = guest.ARCH_STR
        self.target = host.ARCH_STR
        self.split_point = 0.2
        self.data = None
        self.tokenized_data = None
        # 数据预处理
        if self.JSON_PATH:  # 如果有数据，直接加载，不编译
            self.pm = preprocess_module(cfile, COMPILE_ENABLE=False)
        else:               # 如果没有数据，先编译，再预处理
            self.pm = preprocess_module(cfile, COMPILE_ENABLE=True)
            self.pm.analyze(STORE_ENABLE=True, CFG_ENABLE=True, BIN_ENABLE=False)   

    def load_data(self, data_lists):
        insns = {}
        guest_insns = []
        host_insns = []
        for data_list in data_lists:
            for ts in data_list['translation']:
                guest_insns.append(ts['guest_insns'])
                host_insns.append(ts['host_insns'])
        insns = {
            self.source : guest_insns,
            self.target : host_insns
        }
        return insns

    def extract_data(self):
        if self.JSON_PATH:
            self.pm.load_data(self.JSON_PATH)
        # 过滤 json 数据信息，整合为 dictionary
        dict_data = self.load_data(self.pm.data_lists)
        # 使用 Dataset 类加载 dictionary 数据
        all_data = Dataset.from_dict(dict_data)
        # 划分测试集和训练集：test_size = 0.2
        self.data = all_data.train_test_split(test_size=self.split_point)
        print(self.data)
    
    # ======== Model 相关函数 ========= #
    def tokenize_func(self, examples):
        source_insns = [data for data in examples[self.source]]
        target_insns = [data for data in examples[self.target]]
        model_inputs = self.tokenizer(source_insns, text_target=target_insns, max_length=512, padding=True, truncation=True)
        return model_inputs

    def model_prepare(self):
        self.extract_data()
        # 初始化 tokenizer，将数据转化为 token
        print(colors.fg.BLUE + "Tokenizing..." + colors.RESET)
        self.checkpoint = "t5-small"
        self.tokenizer = AutoTokenizer.from_pretrained(self.checkpoint)
        self.tokenized_data = self.data.map(self.tokenize_func, batched=True)
        self.data_collator = DataCollatorForSeq2Seq(tokenizer=self.tokenizer, model=self.checkpoint)
    
    def model_init(self):
        print(colors.fg.BLUE + "Model initializing..." + colors.RESET)
        self.model = AutoModelForSeq2SeqLM.from_pretrained(self.checkpoint)
        # 创建训练参数
        self.training_args = Seq2SeqTrainingArguments(
            output_dir=self.MODEL_DIR,               # 输出目录
            learning_rate=2e-5,
            per_device_train_batch_size=4,
            per_device_eval_batch_size=4,
            weight_decay=0.01,
            save_total_limit=3,
            num_train_epochs=2,
        )
        # 创建训练器
        self.trainer = Seq2SeqTrainer(
            model=self.model,
            args=self.training_args,
            train_dataset=self.tokenized_data["train"],
            eval_dataset=self.tokenized_data["test"],
            tokenizer=self.tokenizer,
        )
    
    def modeL_train(self):
        print(colors.fg.BLUE + "Training..." + colors.RESET)
        self.trainer.train()
        self.trainer.save_model(self.MODEL_DIR)
        print(colors.fg.BLUE + "Training done: model saved to " + self.MODEL_DIR + colors.RESET)

    def learning_test(self):
        self.model_prepare()
        self.model_init()
        self.modeL_train()
        


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
