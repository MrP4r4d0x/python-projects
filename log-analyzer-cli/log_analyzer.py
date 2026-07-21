#!/usr/bin/env python3

import argparse
from pathlib import Path
from collections import Counter

def display_info(title: str, counter: Counter, top_n: int) -> None:   
    print(f"\n{3 * '='} Топ {top_n} {title} {3 * '='}")
    for value, count in counter.most_common(top_n):
        print(f"{value}: {count}")

def read_file(file: str, top_n: int) -> None:
    ip_arr, code_arr, url_arr = Counter(), Counter(), Counter()
    with open(file, 'r') as f:
        for i in f:
            values = i.split()

            if len(values) >= 9:
                ip_arr.update([values[0]])
                code_arr.update([values[8]])
                url_arr.update([values[6]])

    display_info("IP-адресов", ip_arr, top_n)
    display_info("URL", url_arr, top_n)
    display_info("кодов ответа", code_arr, top_n)
    
def main() -> None:
    parser = argparse.ArgumentParser(description='Парсинг логов')
    parser.add_argument("-f", "--file", dest="file", required=True, help="Путь к файлу")
    parser.add_argument("--top", dest="top_n", default=10, type=int)
    args = parser.parse_args()
    file_path = Path(args.file)
    if file_path.is_file():
        read_file(args.file, args.top_n)
    else:
        print("Такого файла не существует")

if __name__=="__main__":
    main()
