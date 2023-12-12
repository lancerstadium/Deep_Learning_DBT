# learning_utils.py

import os
import sys
import angr
from color_cls import colors
from transformers import pipeline, AutoTokenizer, DataCollatorForSeq2Seq, AutoModelForSeq2SeqLM, Seq2SeqTrainingArguments, Seq2SeqTrainer
from preprocess_utils import preprocess_module
from compile_utils import host, guest


class learning_module:
    def __init__(self, cfile):
        self.pm = preprocess_module(cfile)
        self.pm.analyze(STORE_ENABLE=False)
        self.data = []
        self.source = guest.ARCH_STR
        self.target = host.ARCH_STR
    
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
                    self.source : ts['guest_insns'],
                    self.target : ts['host_insns']
                }
                self.data.append(temp)
    
    def store_data(self, path="./test/temp_data.json"):
        self.pm.store_data(path)
    
    def load_data(self, path="./test/temp_data.json"):
        self.pm.load_data(path)
    
    def tokenizer_func(self):
        self.extract_data()
        self.checkpoint = "t5-small"
        self.tokenizer = AutoTokenizer.from_pretrained(self.checkpoint)
        prefix = f"translate {self.source} to {self.target}: "
        inputs = [prefix + insns[self.source] for insns in self.data]
        targets = [insns[self.target] for insns in self.data]
        model_inputs = self.tokenizer(inputs, text_target=targets, max_length=128, truncation=True)
        self.data_collator = DataCollatorForSeq2Seq(tokenizer=self.tokenizer, model=self.checkpoint)
        return model_inputs
    
    def training_func(self):
        self.tokenized_data = self.tokenizer_func()
        self.model = AutoModelForSeq2SeqLM.from_pretrained(self.checkpoint)
        self.training_args = Seq2SeqTrainingArguments(
            output_dir="model",
            evaluation_strategy="epoch",
            learning_rate=2e-5,
            per_device_train_batch_size=16,
            per_device_eval_batch_size=16,
            weight_decay=0.01,
            save_total_limit=3,
            num_train_epochs=2,
            predict_with_generate=True,
            fp16=True,
            push_to_hub=True,
        )
        self.trainer = Seq2SeqTrainer(
            model=self.model,
            args=self.training_args,
            train_dataset=self.tokenized_data["train"],
            eval_dataset=self.tokenized_data["test"],
            tokenizer=self.tokenizer,
            data_collator=self.data_collator,
            # compute_metrics=compute_metrics,
        )
        self.trainer.train()

    def learning_test(self):
        self.training_func()
        


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
