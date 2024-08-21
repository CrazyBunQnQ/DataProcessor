import os
from datetime import datetime

exclude_file_list = ['emerging-deleted.rules', 'emerging-info.rules', 'tor.rules']


def merge_rules(input_dir, output_file):
    # 获取当前日期作为文件名一部分
    current_date = datetime.now().strftime('%Y-%m-%d')
    output_filename = f'emerging-all-{current_date}.rules'

    # 确保输入目录存在并且是一个目录
    if not os.path.exists(input_dir) or not os.path.isdir(input_dir):
        print(f"Error: Directory '{input_dir}' does not exist.")
        return

    # 获取目录下所有的 .rules 文件
    rules_files = [f for f in os.listdir(input_dir) if f.endswith('.rules')]

    # 如果目录下没有 .rules 文件则退出
    if not rules_files:
        print(f"No .rules files found in '{input_dir}'.")
        return

    # 打开输出文件准备写入
    with open(output_file, 'w') as output:
        for rules_file in rules_files:
            # 判断文件名是否属于 exclude_file_list
            if rules_file in exclude_file_list:
                continue
            file_path = os.path.join(input_dir, rules_file)
            with open(file_path, 'r') as input_file:
                output.write(f"# File: {rules_file}\n")
                output.write(input_file.read())
                output.write('\n')

    print(f"Merged {len(rules_files)} .rules files into '{output_filename}'.")


# 调用函数来合并规则文件
merge_rules('./rules', f'emerging-all-{datetime.now().strftime("%Y-%m-%d")}.rules')
