import argparse
import subprocess
import requests
import os
import json
from datetime import datetime
from termcolor import colored
import time
import itertools
import threading
import sys
import concurrent.futures


def spinner(msg):
    for c in itertools.cycle(['💀', '☠️ ', '👻', '🕷️']):
        if spinner_done:
            break
        print(f"\r{msg} {c}", end="", flush=True)
        time.sleep(0.2)


def banner():
    print(colored(r"""
     ██████╗ ██████╗ ███████╗███████╗██╗███╗   ██╗     █████╗ ██╗  ██╗
    ██╔════╝██╔═══██╗██╔════╝██╔════╝██║████╗  ██║    ██╔══██╗╚██╗██╔╝
    ██║     ██║   ██║█████╗  █████╗  ██║██╔██╗ ██║    ███████║ ╚███╔╝ 
    ██║     ██║   ██║██╔══╝  ██╔══╝  ██║██║╚██╗██║    ██╔══██║ ██╔██╗ 
    ╚██████╗╚██████╔╝██║     ██║     ██║██║ ╚████║    ██║  ██║██╔╝ ██╗
     ╚═════╝ ╚═════╝ ╚═╝     ╚═╝     ╚═╝╚═╝  ╚═══╝    ╚═╝  ╚═╝╚═╝  ╚═╝ v1.0
                          [ Coffin_AK - Auto Recon Tool ]
    """, "green"))


def check_requirements():
    required_tools = ["subfinder", "assetfinder", "gau"]
    missing = []
    for tool in required_tools:
        if subprocess.call(f"which {tool}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            missing.append(tool)
    if missing:
        print(colored("[!] Missing tools detected:", "red"), ", ".join(missing))
        print(colored("[*] Attempting to install...", "cyan"))
        for tool in missing:
            try:
                subprocess.run(f"go install github.com/projectdiscovery/{tool}/cmd/{tool}@latest", shell=True, check=True)
                print(colored(f"[+] Installed {tool}", "green"))
            except subprocess.CalledProcessError:
                print(colored(f"[!] Failed to install {tool}. Please install it manually.", "red"))
        print(colored("[!] Restart the script after installation if needed.", "yellow"))


def run_command(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout.strip().splitlines()
    except Exception as e:
        return []


def enumerate_subdomains(domain):
    subdomains = set()

    print(colored("[*] Running subfinder... 💀", "cyan"))
    subdomains.update(run_command(f"subfinder -d {domain} -silent"))

    print(colored("[*] Running assetfinder... 👻", "cyan"))
    subdomains.update(run_command(f"assetfinder --subs-only {domain}"))

    return sorted(set(sub for sub in subdomains if domain in sub))


def check_url_alive(url):
    for scheme in ["http", "https"]:
        full_url = f"{scheme}://{url}"
        try:
            response = requests.get(full_url, timeout=3)
            if response.status_code < 400:
                return full_url
        except requests.RequestException:
            continue
    return None


def check_alive(subdomains):
    print(colored("[*] Checking for alive subdomains using Python requests... ⚡", "yellow"))
    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(check_url_alive, sub): sub for sub in subdomains}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                alive.append(result)
    if not alive:
        print(colored("[!] No alive subdomains found.", "red"))
    return alive


def crawl_urls(subdomains):
    urls = set()
    for sub in subdomains:
        gau_out = run_command(f"gau {sub}")
        urls.update(gau_out)
    return sorted(urls)


def save_output(output_dir, filename, data):
    path = os.path.join(output_dir, filename)
    with open(path, 'w') as f:
        for item in data:
            f.write(f"{item}\n")
    print(colored(f"[+] Saved {filename} ({len(data)} lines)", "green"))


def main():
    global spinner_done
    banner()
    check_requirements()

    parser = argparse.ArgumentParser(description='Coffin_AK - Automated Recon Tool')
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-o', '--output', default='output', help='Output directory')
    parser.add_argument('-alive', action='store_true', help='Run alive subdomain checking')
    parser.add_argument('-url', action='store_true', help='Run URL crawling')

    try:
        args = parser.parse_args()
    except SystemExit:
        print(colored("[!] Invalid arguments provided. Use -h for help.", "red"))
        sys.exit(1)

    os.makedirs(args.output, exist_ok=True)

    spinner_done = False
    t = threading.Thread(target=spinner, args=("[🔍] Enumerating subdomains",))
    t.start()
    subs = enumerate_subdomains(args.domain)
    spinner_done = True
    t.join()
    print("\n")

    save_output(args.output, 'subdomains.txt', subs)

    if args.alive:
        alive = check_alive(subs)
        save_output(args.output, 'alive.txt', alive)
    else:
        alive = subs

    if args.url:
        urls = crawl_urls(alive)
        save_output(args.output, 'urls.txt', urls)

    print(colored("\n[✔] Recon completed. All data saved in:", "green"), os.path.abspath(args.output))


if __name__ == '__main__':
    main()
