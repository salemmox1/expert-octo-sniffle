import os
import random
import subprocess
import threading
import time
import requests
import ipaddress
import re
from colorama import Fore, init, Style, Back

init(autoreset=True)

# لوحة الألوان المتقدمة
G = Fore.GREEN
R = Fore.RED
Y = Fore.YELLOW
CY = Fore.CYAN
W = Fore.WHITE
B = Fore.BLUE
MAG = Fore.MAGENTA
LC = Fore.LIGHTCYAN_EX
LB = Fore.LIGHTBLUE_EX
LR = Fore.LIGHTRED_EX
RE = Style.RESET_ALL

COMPANIES = {
    "1": {"name": "Amazon AWS (3.x)", "prefix": "3"},
    "2": {"name": "Amazon AWS (52.x)", "prefix": "52"},
    "3": {"name": "Microsoft Azure", "prefix": "13"},
    "4": {"name": "Google Cloud", "prefix": "34"},
    "5": {"name": "Akamai / Cloud (122.x)", "prefix": "122"},
    "6": {"name": "Global Networks (2.x)", "prefix": "2"},
    "7": {"name": "DigitalOcean", "prefix": "104"},
    "8": {"name": "Oracle Cloud", "prefix": "140"}
}

# --- وظائف الجلب من GitHub (ipverse) ---
def fetch_country_ips(country_id):
    country_id = country_id.lower().strip()
    url = f"https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/{country_id}/ipv4-aggregated.txt"
    print(f"\n{LC}[*] Connecting to ipverse Database for {country_id.upper()}...{RE}")
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            return [line.strip() for line in response.text.splitlines() if line.strip() and not line.startswith("#")]
        else:
            print(f"{R}[!] Error: Could not find data for '{country_id}'.{RE}")
            return []
    except:
        print(f"{R}[!] Connection Failed!{RE}")
        return []

def extract_sample_ips(cidr_list, limit_input):
    ips = []
    is_all = str(limit_input).lower() == "all"
    print(f"{Y}[*] Extracting IPs from {len(cidr_list)} blocks...{RE}")
    for block in cidr_list:
        try:
            network = ipaddress.ip_network(block)
            count = 0
            for ip in network.hosts():
                ips.append(str(ip))
                if not is_all:
                    count += 1
                    if count >= int(limit_input): break
        except: continue
    return ips

# --- وظائف التصفية الذكية ---
def ping_check(ip):
    try:
        res = subprocess.call(['ping', '-c', '1', '-W', '1', ip], 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res == 0
    except: return False

def filter_alive_ips(ip_list, threads_count=150):
    alive_count = 0
    total = len(ip_list)
    processed = 0
    start_time = time.time()
    open("IP.txt", "w").close()
    print(f"\n{LC}>>> {W}STARTING ULTRA FILTER ON {Y}{total} {W}IPs {LC}<<<{RE}")
    lock = threading.Lock()

    def worker(ips):
        nonlocal processed, alive_count
        for ip in ips:
            status = ping_check(ip)
            with lock:
                processed += 1
                if status:
                    alive_count += 1
                    with open("IP.txt", "a") as f: f.write(ip + "\n")
                if processed % 10 == 0 or processed == total:
                    elapsed = time.time() - start_time
                    speed = processed / elapsed if elapsed > 0 else 1
                    remaining = total - processed
                    eta = remaining / speed
                    eta_str = f"{int(eta//60)}m {int(eta%60)}s" if eta > 60 else f"{int(eta)}s"
                    print(f"\r{LB}[{W}{processed}{LB}/{W}{total}{LB}] {LC}ALIVE: {G}{alive_count} {LB}| {Y}ETA: {eta_str} {RE}", end="", flush=True)

    chunks = [ip_list[i::threads_count] for i in range(threads_count)]
    threads = []
    for chunk in chunks:
        if not chunk: continue
        t = threading.Thread(target=worker, args=(chunk,))
        t.daemon = True
        t.start()
        threads.append(t)
    for t in threads: t.join()
    print(f"\n\n{Back.GREEN}{W} DONE {RE} {G}SCAN FINISHED. {W}{alive_count} {G}IPs SAVED TO IP.txt.{RE}")

# --- وظيفة الأنماط الذكية (Pattern Logic) ---
def generate_pattern_ips(pattern):
    print(f"\n{LC}[*] {W}EXPANDING SMART PATTERN LOGIC...{RE}")
    def expand_part(part):
        options = []
        if 'x' in part:
            for digit in range(10):
                new_part = part.replace('x', str(digit), 1)
                options.extend(expand_part(new_part))
            return options
        else:
            val = int(part)
            return [str(val)] if 0 <= val <= 255 else []
    parts = pattern.split('.')
    if len(parts) != 4: return []
    try:
        p1, p2, p3, p4 = expand_part(parts[0]), expand_part(parts[1]), expand_part(parts[2]), expand_part(parts[3])
        return list(set([f"{i}.{j}.{k}.{l}" for i in p1 for j in p2 for k in p3 for l in p4]))
    except: return []

# --- وظيفة محول الملفات ---
def masscan_converter():
    print(f"\n{B}1. {LC}IP:PORT {W}-> {G}IP ONLY")
    print(f"{B}2. {LC}IP ONLY {W}-> {G}IP:PORT {RE}")
    sub_choice = input(f"\n{Y}SELECT CONVERSION: {W}").strip()
    file_name = input(f"{W}SOURCE FILE: {RE}").strip()
    if not os.path.exists(file_name): return []
    results = []
    with open(file_name, "r") as f: lines = f.readlines()
    if sub_choice == '1':
        for line in lines:
            ip = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", line)
            if ip: results.append(ip[0])
    elif sub_choice == '2':
        port = input(f"{W}PORT: {RE}").strip()
        for line in lines:
            clean_ip = line.strip()
            if clean_ip: results.append(f"{clean_ip}:{port}")
    return results

def main():
    os.system('clear' if os.name != 'nt' else 'cls')
    print(f"{MAG}#################################################")
    print(f"{MAG}#      {LC}NL MASTER GENERATOR - {W}ULTIMATE v8.5{MAG}      #")
    print(f"{MAG}#    {CY}(Full 0-255 Range & ipverse Support){MAG}       #")
    print(f"{MAG}#################################################{RE}\n")
    
    print(f"{LC}[1] {G}Reference IP (Neighbors Scan)")
    print(f"{LC}[2] {CY}Company Networks (Massive Blocks)")
    print(f"{LC}[3] {Y}Target by Country (Real ipverse Data)")
    print(f"{LC}[4] {LR}DEEP GLOBAL SCAN (Full 16.7M IPs)")
    print(f"{LC}[5] {G}SMART PATTERN (Logic X Engine)")
    print(f"{LC}[6] {W}MASSCAN/IP CONVERTER (File Tool){RE}")
    
    mode_choice = input(f"\n{LC}MODE >> {W}").strip()
    
    target_ips = []
    if mode_choice == '1':
        ref_ip = input(f"{W}IP: {RE}").strip()
        count_in = input(f"{W}COUNT (or all): {RE}").strip().lower()
        parts = ref_ip.split('.')
        prefix = f"{parts[0]}.{parts[1]}.{parts[2]}."
        target_ips = [f"{prefix}{i}" for i in range(255)] if count_in == 'all' else [f"{prefix}{i}" for i in range(int(count_in))]

    elif mode_choice == '2':
        for k, v in COMPANIES.items(): print(f"{B}[{k}] {LC}{v['name']}{RE}")
        choices = input(f"\n{Y}SELECT ID: {W}").strip()
        count_in = input(f"{W}IPs PER CO: {RE}").strip().lower()
        for c in choices:
            if c in COMPANIES:
                p = COMPANIES[c]['prefix']
                for _ in range(5000 if count_in == 'all' else int(count_in)):
                    target_ips.append(f"{p}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}")

    elif mode_choice == '3':
        c_code = input(f"{W}COUNTRY ID (e.g. us, sa, eg): {RE}").lower().strip()
        cidrs = fetch_country_ips(c_code)
        if cidrs:
            choice = input(f"{Y}Mode: (1) CIDR Blocks or (2) Extract Samples? {W}").strip()
            if choice == '1':
                with open("IP.txt", "w") as f:
                    for line in cidrs: f.write(line + "\n")
                print(f"{G}[SUCCESS] Blocks saved for Masscan.{RE}"); return
            else:
                limit_in = input(f"{W}IPs per block (e.g. 5 or all): {RE}").strip().lower()
                target_ips = extract_sample_ips(cidrs, limit_in)

    elif mode_choice == '5':
        pattern = input(f"{W}PATTERN (use x): {RE}").strip()
        target_ips = generate_pattern_ips(pattern)

    elif mode_choice == '6':
        target_ips = masscan_converter()

    if target_ips:
        print(f"\n{LC}[*] {W}IPS IN BUFFER: {Y}{len(target_ips)}{RE}")
        verify = input(f"{MAG}PING VERIFICATION? (y/n): {W}").lower()
        if verify == 'y': filter_alive_ips(target_ips)
        else:
            with open("IP.txt", "w") as f:
                for ip in target_ips: f.write(ip + "\n")
            print(f"\n{Back.GREEN}{W} SUCCESS {RE} {G}SAVED TO IP.txt{RE}")

if __name__ == "__main__":
    main()

