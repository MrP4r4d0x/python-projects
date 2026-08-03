#!/usr/bin/env python3

import argparse
from pathlib import Path
from collections import Counter, defaultdict
import re

# ==================== РЕАЛИЗАЦИЯ ПАРСЕРОВ ====================

class NginxParser():
    def __init__(self) -> None:
        self.log_pattern = re.compile(r"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<date>[^\]]+)\]\s\"(?P<method>[A-Z]+)\s(?P<url>\S*)(?:\sHTTP\S*)?\"\s(?P<code>\d{3})")
        self.ip_analytics = defaultdict(lambda:{
            "date": Counter(),
            "method": Counter(),
            "url": Counter(),
            "code": Counter(),
            "total_requests": 0
        })

    def parser_log(self, line: str) -> None:
        match = self.log_pattern.match(line)

        if not match:
            return
        
        dataset = match.groupdict()
        self.ip_analytics[dataset["ip"]]["date"].update([dataset["date"]])
        self.ip_analytics[dataset["ip"]]["method"].update([dataset["method"]])
        self.ip_analytics[dataset["ip"]]["url"].update([dataset["url"]])
        self.ip_analytics[dataset["ip"]]["code"].update([dataset["code"]])
        self.ip_analytics[dataset["ip"]]["total_requests"] += 1

    def display(self, top_n: int) -> None:
        print(f"\n{3 * '='} ДЕТАЛЬНЫЙ АНАЛИЗ ТОП-{top_n} АКТИВНЫХ IP {3 * '='}")
        sort_values = sorted(self.ip_analytics.items(), key=lambda item: item[1]['total_requests'], reverse=True)
        for ip, info in sort_values[:top_n]:
            print(f"\n[+] IP-адрес: {ip} (Всего запросов: {info['total_requests']})")

            print("\tСамые запрашиваемые URL:")
            for url, count in info["url"].most_common(3):
                print(f"\t\t- {url}: {count} раз ({(count / info['total_requests']) * 100:.1f}%)")

            print("\tКоды ответов:")
            for code, count in info["code"].most_common(3):
                print(f"\t\t- {code}: {count} раз ({(count / info['total_requests']) * 100:.1f}%)")

            print("\tМетоды:")
            for method, count in info["method"].most_common(3):
                print(f"\t\t- {method}: {count} раз ({(count / info['total_requests']) * 100:.1f}%)")

            print("\tДаты:")
            for date, count in info["date"].most_common(3):
                print(f"\t\t- {date}: {count} раз ({(count / info['total_requests']) * 100:.1f}%)")

        
class SyslogParser():
    def __init__(self) -> None:

        self.fail_passwd = re.compile(r"^(?P<date>\w+\s+\d{1,2}\s\S+|\S+)\s\S+\ssshd\[(?P<pid>\d+)\]:\s(?P<error>Failed)\spassword\sfor\s(?:invalid user\s)?(?P<name>\S+)\sfrom\s(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\sport\s(?P<port>\d+)")
        self.con_clos = re.compile(r"^(?P<date>\w+\s+\d{1,2}\s\S+|\S+)\s\S+\ssshd\[(?P<pid>\d+)\]:\s(?P<error>Connection)\sclosed\sby\s(?:authenticating\suser\s|invalid\suser\s)?(?P<name>\S+)\s(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\sport\s(?P<port>\d+)")
        self.inv_usr = re.compile(r"^(?P<date>\w+\s+\d{1,2}\s\S+|\S+)\s\S+\ssshd\[(?P<pid>\d+)\]:\s(?P<error>Invalid)\suser\s(?P<name>\S+)\sfrom\s(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\sport\s(?P<port>\d+)")
        self.authen_fail = re.compile(r"^(?P<date>\w+\s+\d{1,2}\s\S+|\S+)\s\S+\ssshd\[(?P<pid>\d+)\]:\s\S+\s(?P<error>authentication)\sfailure;.*?logname=(?P<logname>\S*).*?uid=(?P<uid>\d*).*?euid=(?P<euid>\d*).*?tty=(?P<tty>\S*).*?ruser=(?P<ruser>\S*).*?rhost=(?P<ip>\d+(?:\.\d{1,3}){3}).*?user=(?P<name>\S*)")

        self.ip_analytics = defaultdict(lambda: {
            "Failed": {
                "date": Counter(),
                "pid": Counter(),
                "name": Counter(),
                "port": Counter(),
                "total_requests": 0

            },
            "Connection": {
                "date": Counter(),
                "pid": Counter(),
                "name": Counter(),
                "port": Counter(),
                "total_requests": 0
            },
            "Invalid": {
                "date": Counter(),
                "pid": Counter(),
                "name": Counter(),
                "port": Counter(),
                "total_requests": 0
            },
            "authentication": {
                "date": Counter(),
                "pid": Counter(),
                "logname": Counter(),
                "uid": Counter(),
                "euid": Counter(),
                "tty": Counter(),
                "ruser": Counter(),
                "name": Counter(),
                "total_requests": 0
            }
        })

    def parser_log(self, line: str) -> None:
        if "Invalid user" in line:
            match = self.inv_usr.match(line)
        elif "authentication failure" in line:
            match = self.authen_fail.match(line)
        elif "Connection closed by" in line:
            match = self.con_clos.match(line)
        elif "Failed password" in line:
            match = self.fail_passwd.match(line)
        else:
            return

        if not match:
            return

        dataset = match.groupdict()
        ip = dataset.pop("ip")
        error = dataset.pop("error")

        for i, j in dataset.items():
            self.ip_analytics[ip][error][i].update([j])
        self.ip_analytics[ip][error]["total_requests"] += 1
    
    def display(self, top_n: int) -> None:
        values_info = {
            "date": "Дата и время события",
            "pid": "Идентификаторы процесса (PID)",
            "name": "Имя пользователя (или процесса)",
            "port": "Сетевые или терминальные порты",
            "logname": "Исходные логины пользователей (logname)",
            "uid": "Реальные идентификаторы пользователей (UID)",
            "euid": "Эффективные идентификаторы пользователей (EUID)",
            "tty": "Имена терминалов (TTY)",
            "ruser": "Имена удалённых пользователей (ruser)"
        }
        print(f"\n{3 * '='} ДЕТАЛЬНЫЙ АНАЛИЗ ТОП-{top_n} АКТИВНЫХ IP {3 * '='}")
        sort_values = sorted(self.ip_analytics.items(), key=lambda item: sum(info["total_requests"] for info in item[1].values()), reverse=True)
        for ip, info in sort_values[:top_n]:
            total_requests = sum(v["total_requests"] for v in info.values())
            print(f"\n[+] IP-адрес: {ip} (Всего запросов: {total_requests})")
            for error, values in info.items():
                print(f"\tОшибка {error}: {values['total_requests']}")
                if values['total_requests'] == 0:
                    continue
                for i, v in values.items():
                    if i == "total_requests":
                        continue
                    print(f"\t\t{values_info[i]}:")
                    for method, count in v.most_common(3):
                        print(f"\t\t\t- {method}: {count} раз ({(count / values['total_requests']) * 100:.1f}%)")              

class JsonAppParser:
    def __init__(self):
        pass

class DatabaseSlowQueryParser:
    def __init__(self):
        pass
# ==================== ГЛАВНАЯ СКРИПТА ====================

def read_file(file: str, top_n: int, type: str) -> None:

    if type == "nginx":
        parser_file = NginxParser()
    elif type == "syslog":
        parser_file = SyslogParser()
    else:
        print("Введен некоректный тип файла (nginx/syslog)")
        return
         
    with open(file, 'r') as f:
        for i in f:
            parser_file.parser_log(i)

    parser_file.display(top_n)
    

def main() -> None:

    parser = argparse.ArgumentParser(description='Парсинг логов')

    parser.add_argument("-f", "--file", dest="file", required=True, help="Путь к файлу")
    parser.add_argument("-t", "--type", dest="type", required=True, help="Тип обрабатываемого файла (nginx/syslog)")
    parser.add_argument("--top", dest="top_n", default=10, type=int)

    args = parser.parse_args()

    file_path = Path(args.file)

    if file_path.is_file() and args.type in ["nginx", "syslog"]:
        read_file(args.file, args.top_n, args.type)
    elif args.type not in ["nginx", "syslog"]:
         print("Введен некоректный тип файла (nginx/syslog)")
    else:
        print("Такого файла не существует")

if __name__=="__main__":
    main()
