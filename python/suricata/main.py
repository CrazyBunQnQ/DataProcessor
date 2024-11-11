'''
Main module to download and process rule files.
'''
import os
import sys
import tarfile

import requests

from file_processor import process_files


def download_rules(version):
    """
    Download the rules file from the specified URL using the version number.
    https://rules.emergingthreats.net/open/suricata-5.0.0/emerging.rules.tar.gz
    """
    url = f"https://rules.emergingthreats.net/open/suricata-{version}/emerging.rules.tar.gz"
    response = requests.get(url)
    if response.status_code == 200:
        with open("emerging.rules.tar.gz", "wb") as file:
            file.write(response.content)
        return True
    else:
        print(f"Failed to download the file: HTTP {response.status_code}")
        return False


def extract_rules():
    """
    将下载的 tar.gz 文件解压到当前目录中。
    """
    if os.path.exists("emerging.rules.tar.gz"):
        with tarfile.open("emerging.rules.tar.gz", "r:gz") as tar:
            tar.extractall()
        return True
    else:
        print("Downloaded file is not available.")
        return False


def main(version, redownload=False):
    """
    Main function that orchestrates the downloading, extracting, and processing of rule files.
    """
    # 如果 csa.rules 存在则删除文件
    if os.path.exists("csa.rules"):
        os.remove("csa.rules")
    if not os.path.exists("emerging.rules.tar.gz") or redownload:
        if download_rules(version):
            if extract_rules():
                process_files()
    else:
        process_files()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        main('5.0.0')
    else:
        main(sys.argv[1])
