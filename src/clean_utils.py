# clean_utils.py
import os
import sys


def delete_files_with_suffix(directory, suffix_list, PRINT_ENABLE=False):
    '''
    说明：删除指定目录下的指定后缀的文件
    :param directory: 目录
    :param suffix_list: 后缀列表
    :return: None
    '''
    for root, dirs, files in os.walk(directory):
        for file in files:
            for suffix in suffix_list:
                if file.endswith(suffix):
                    file_path = os.path.join(root, file)
                    os.remove(file_path)
                    if PRINT_ENABLE:
                        print(f"Deleted: {file_path}")

# unit test
from clean_utils import delete_files_with_suffix

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python clean_utils.py <directory>, use `../test` as default.")
        directory = "../test"
    else:
        directory = sys.argv[1]

    if not os.path.isdir(directory):
        print(f"The specified directory '{directory}' does not exist.")
        sys.exit(1)
    suffix_list = ['.out', 'png']  # 需要删除的文件后缀列表
    delete_files_with_suffix(directory, suffix_list)
