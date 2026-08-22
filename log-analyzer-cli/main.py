#!/usr/bin/env python3

import argparse 
from pathlib import Path 
from collections import Counter, defaultdict
import re 
import json
from datetime import datetime 

# ==================== РЕАЛИЗАЦИЯ ПАРСЕРОВ ====================

class IpStats:
    def __init__(self) -> None:
        self.categorical = defaultdict(Counter)
        self.numeric = defaultdict(list)
        self.errors = defaultdict(list)
        self.total_requests = 0

class NginxParser:
    def __init__(self, time: str) -> None:
        self.log_pattern = re.compile(r"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<date>[^\]]+)\]\s\"(?P<method>[A-Z]+)\s(?P<url>\S*)(?:\sHTTP\S*)?\"\s(?P<code>\d{3})")
        self.ip_analytics = defaultdict(IpStats)
        self.time = time

        self.values_info = {
            "code": "Коды ответов",            
            "url": "Самые запрашиваемые URL",
            "method": "Методы",
            "date": "Даты",
        }

    def parser_log(self, line: str) -> None:
        match = self.log_pattern.match(line)

        if not match:
            return
        
        dataset = match.groupdict()

        if not dataset.get("ip"):
            return
        ip = dataset.pop("ip")

        if dataset.get("date"):
            date = dataset.pop("date")
            date_str = processing_date(date, "%d/%b/%Y:%H:%M:%S %z", self.time)
            if date_str:
                self.ip_analytics[ip].categorical["date"].update([date_str])
            else:
                self.ip_analytics[ip].errors["date_parse_failed"].append(date)
        else:
            self.ip_analytics[ip].errors["date_parse_failed"].append("Отсутствует дата")

        for index, value in dataset.items():
            if value:
                self.ip_analytics[ip].categorical[index].update([value])
            else:
                self.ip_analytics[ip].errors[f"{index}_parse_failed"].append(f"Отсутствует {index}")
        self.ip_analytics[ip].total_requests += 1
        
class SyslogParser():
    def __init__(self, time: str) -> None:

        self.fail_passwd = re.compile(r"^(?P<date>\w+\s+\d{1,2}\s\S+|\S+)\s\S+\ssshd\[(?P<pid>\d+)\]:\s(?P<error>Failed)\spassword\sfor\s(?:invalid user\s)?(?P<name>\S+)\sfrom\s(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\sport\s(?P<port>\d+)")
        self.con_clos = re.compile(r"^(?P<date>\w+\s+\d{1,2}\s\S+|\S+)\s\S+\ssshd\[(?P<pid>\d+)\]:\s(?P<error>Connection)\sclosed\sby\s(?:authenticating\suser\s|invalid\suser\s)?(?P<name>\S+)\s(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\sport\s(?P<port>\d+)")
        self.inv_usr = re.compile(r"^(?P<date>\w+\s+\d{1,2}\s\S+|\S+)\s\S+\ssshd\[(?P<pid>\d+)\]:\s(?P<error>Invalid)\suser\s(?P<name>\S+)\sfrom\s(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\sport\s(?P<port>\d+)")
        self.authen_fail = re.compile(r"^(?P<date>\w+\s+\d{1,2}\s\S+|\S+)\s\S+\ssshd\[(?P<pid>\d+)\]:\s\S+\s(?P<error>authentication)\sfailure;.*?logname=(?P<logname>\S*).*?uid=(?P<uid>\d*).*?euid=(?P<euid>\d*).*?tty=(?P<tty>\S*).*?ruser=(?P<ruser>\S*).*?rhost=(?P<ip>\d+(?:\.\d{1,3}){3}).*?user=(?P<name>\S*)")

        self.ip_analytics = defaultdict(IpStats)
        self.time = time

        self.values_info = {
            "error": "Ошибка",            
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

        if not dataset.get("ip"):
            return 
        ip = dataset.pop("ip")

        if dataset.get("date"):
            date = dataset.pop("date")
            date_str = processing_date(" ".join(date.split()), "%b %d %H:%M:%S", self.time)
            if date_str:
                self.ip_analytics[ip].categorical["date"].update([date_str])
            else:
                self.ip_analytics[ip].errors["date_parse_failed"].append(date)
        else:
            self.ip_analytics[ip].errors["date_parse_failed"].append("Отсутствует дата")

        for index, value in dataset.items():
            if value:
                self.ip_analytics[ip].categorical[index].update([value])
            else:
                self.ip_analytics[ip].errors[f"{index}_parse_failed"].append(f"Отсутствует {index}")
        self.ip_analytics[ip].total_requests += 1
    
class JsonAppParser:
    def __init__(self, time: str):
        self.ip_analytics = defaultdict(IpStats)
        self.time = time
        self.values_info = {
            "level": "Уровень логирования (INFO, ERROR, DEBUG...)",
            "service": "Сервис или микросервис",
            "message": "Текст сообщения",
            "user_id": "Идентификатор пользователя",
            "status_code": "HTTP-код ответа",
            "component": "Компонент / модуль",
            "error_code": "Код ошибки (бизнес-логика)",
            "exception": "Тип исключения (класс ошибки)",
            "duration_ms": "Длительность обработки, мс",
            "response_time": "Время ответа, мс"
        }

    def flatten_dict(self, data: dict, old_key='', sep='_') -> dict:
        arr = []
        for index, value in data.items():
            new_key = f"{old_key}{sep}{index}" if old_key else index
            if isinstance(value, dict):
                arr.extend(self.flatten_dict(value, new_key).items())
            else:
                arr.append((new_key, value))
        return dict(arr)

    def parser_log(self, line: str) -> None:
        try:
            data = json.loads(line)
            ip = data.pop("ip")
        except Exception:
            return

        if not ip:
            return

        if data.get("timestamp"):
            date = data.pop("timestamp")
            date_str = processing_date(date, "%Y-%m-%dT%H:%M:%SZ", self.time)
            if date_str:
                self.ip_analytics[ip].categorical["timestamp"].update([date_str])
            else:
                self.ip_analytics[ip].errors["date_parse_failed"].append(date)
        else:
            self.ip_analytics[ip].errors["date_parse_failed"].append("Отсутствует дата")

        flat_dict = self.flatten_dict(data)
        
        for index, value in flat_dict.items():
            if value:
                if index in ["duration_ms", "response_time"] and isinstance(value, (int, float)):
                    self.ip_analytics[ip].numeric[index].append(value)
                else:
                    self.ip_analytics[ip].categorical[index].update([value])
            else:
                self.ip_analytics[ip].errors[f"{index}_parse_failed"].append(f"Отсутствует {index}")
        self.ip_analytics[ip].total_requests += 1

class DatabaseSlowQueryParser:
    def __init__(self, time: str):

        self.re_time = re.compile(r"^#\sTime:\s(?P<time>\S+)$")
        self.re_user = re.compile(r"^#\sUser@Host:\s(?P<userhost>\S+)\s@.+\[(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\]\s+Id:\s(?P<id>\d+)$")
        self.re_metrics = re.compile(r"^#\sQuery_time:\s(?P<query_time>\S+)\s+Lock_time:\s(?P<lock_time>\S+)\s+Rows_sent:\s(?P<rows_sent>\d+)\s+Rows_examined:\s(?P<rows_examined>\d+)$")
        self.re_sql_operation = re.compile(r"^\s*(?P<operation>\w+)")
        self.re_sql_fingerprint = re.compile(r"\b\d+(?:[\.\-]?\d*)*\b")

        self.ip_analytics = defaultdict(IpStats)

        self.sql_arr = []
        self.dict_data = dict()
        self.time = time

        self.values_info = {
            "time": "Время выполнения или фиксации запроса",
            "userhost": "Пользователь и хост, выполнившие запрос (User[pass] @ Host)",
            "id": "Идентификатор потока / соединения (Connection ID)",
            "operation": "Тип операции или текст SQL-запроса",
            "fingerprint": "Абстрактный отпечаток (шаблон) запроса без конкретных значений",
            "query_time": "Общее время выполнения запроса (в секундах)",
            "lock_time": "Время, потраченное на ожидание блокировок таблиц",
            "rows_sent": "Количество строк, отправленных клиенту",
            "rows_examined": "Количество строк, проверенных сервером при выборке",
        }

    def parser_log(self, line: str) -> None:

        match = None

        if not line:
            return

        if line.startswith("# Time:"):
            self.finalize()
            match = self.re_time.search(line)
        elif line.startswith("# User@Host:"):
            match = self.re_user.search(line)
        elif line.startswith("# Query_time:"):
            match = self.re_metrics.search(line)
        else:
            self.sql_arr.append(line)
            return
        
        if not match:
            return

        self.dict_data.update(match.groupdict())

    def finalize(self):
        if self.dict_data and self.dict_data.get("ip"):

            ip = self.dict_data.pop("ip")
            sql_txt = "\t\t".join(self.sql_arr)
            sql_match = self.re_sql_operation.search(sql_txt)
            sql_txt = self.re_sql_fingerprint.sub("?", sql_txt)

            if self.dict_data.get("time"):
                date = self.dict_data.pop("time")
                date_str = processing_date(date, "%Y-%m-%dT%H:%M:%S.%f%z", self.time)
                if date_str:
                    self.ip_analytics[ip].categorical["timestamp"].update([date_str])
                else:
                    self.ip_analytics[ip].errors["date_parse_failed"].append(date)
            else:
                self.ip_analytics[ip].errors["date_parse_failed"].append("Отсутствует дата")

            sql_operation = sql_match.group("operation") if sql_match else "UNKNOWN"

            self.ip_analytics[ip].categorical["operation"].update([sql_operation])
            self.ip_analytics[ip].categorical["fingerprint"].update([sql_txt])

            for key, value in self.dict_data.items():
                if value:
                    if key in ["time", "userhost","id"]:
                        self.ip_analytics[ip].categorical[key].update([value])
                    elif key in ["query_time", "lock_time", "rows_sent", "rows_examined"]:
                        try:
                            self.ip_analytics[ip].numeric[key].append(float(value))
                        except ValueError:
                            self.ip_analytics[ip].errors["ValueError"].append(f"{value}")
                else:
                    self.ip_analytics[ip].errors[f"{key}_parse_failed"].append(f"Отсутствует {key}")
            self.ip_analytics[ip].total_requests += 1

        self.dict_data.clear()
        self.sql_arr.clear()

        
        

# ==================== ГЛАВНАЯ СКРИПТА ====================

def display(top_n: int, cl: object, type: str) -> None:

    if type == "db":
        cl.finalize()

    print(f"\n{3 * '='} ДЕТАЛЬНЫЙ АНАЛИЗ ТОП-{top_n} АКТИВНЫХ IP {3 * '='}")
    sort_values = sorted(cl.ip_analytics.items(), key=lambda item: item[1].total_requests, reverse=True)
    for ip, info in sort_values[:top_n]:
        print(f"\n[+] IP-адрес: {ip} (Всего запросов: {info.total_requests})")
        for categoria, values in info.categorical.items():
            if values:
                if cl.values_info.get(categoria):
                    print(f"\t{cl.values_info[categoria]}:")
                else:
                    print(f"\t{categoria}:")
                for value, cnt in values.most_common(3):
                    print(f"\t\t\t- {value}: {cnt} раз ({(cnt / info.total_requests) * 100:.1f}%)")  
        for index, values_list in info.numeric.items():
            if values_list:
                if cl.values_info.get(index):
                    print(f"\t{cl.values_info[index]}:")
                else:
                    print(f"\t{index}:")
                print(f"\t\t- Среднее: {sum(values_list) / len(values_list):.1f}")
                print(f"\t\t- Максимум: {max(values_list)}")
                print(f"\t\t- Минимум: {min(values_list)}")
        if info.errors:
            print("\t[!] Ошибки найденные при обработке:")
            for error_type, error_values in info.errors.items():
                if error_values:
                    print(f"\t\t- {error_type}: {len(error_values)} раз(а)")
                    for sample in error_values[:3]:
                        print(f"\t\t\tПример: {sample}")

def read_file(file: str, top_n: int, type: str, time: str) -> None:

    if type == "nginx":
        parser_file = NginxParser(time)
    elif type == "syslog":
        parser_file = SyslogParser(time)
    elif type == "json":
        parser_file = JsonAppParser(time)
    elif type == "db":
        parser_file = DatabaseSlowQueryParser(time)
    else:
        print("Введен некоректный тип файла (nginx/syslog/json/db)")
        return
         
    with open(file, 'r', encoding='utf-8', errors='replace') as f:
        for i in f:
            parser_file.parser_log(i)

    display(top_n, parser_file, type)

def processing_date(date_str: str, frmt: str, time: str) -> str | None:

    try:
        dt = datetime.strptime(date_str, frmt)

        match time:
            case "Y":
                return dt.strftime("%Y")
            case "m":
                return dt.strftime("%Y-%m")
            case "d":
                return dt.strftime("%Y-%m-%d")
            case "M":
                return dt.strftime("%Y-%m-%d %H:%M")
            case "S":
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            case _:
                return dt.strftime("%Y-%m-%d %H")
            
    except (ValueError, TypeError):
        return None

    
    
def ip_address():
    pass

def main() -> None:

    parser = argparse.ArgumentParser(description='Парсинг логов')

    parser.add_argument("-f", "--file", dest="file", required=True, help="Путь к файлу")
    parser.add_argument("-t", "--type", dest="type", required=True, choices=["nginx", "syslog", "json", "db"], help="Тип обрабатываемого файла")
    parser.add_argument("--time", dest="time", default="H", type=str, choices=["Y", "m", "d", "H", "M", "S"], help="Формат даты и времени")
    parser.add_argument("--top", dest="top_n", default=10, type=int, help="Количество строк")

    args = parser.parse_args()

    file_path = Path(args.file)

    if not file_path.is_file():
        parser.error("Такого файла не существует")
    if args.top_n <= 0:
        parser.error("Количество строк должно быть больше 0")
    read_file(args.file, args.top_n, args.type, args.time)
        

if __name__=="__main__":
    main()
