import argparse
import requests
import urllib.parse
import time
import json
import os
from typing import List, Dict, Optional
from modules.scanners import Scanner
from modules.payloads import PayloadGenerator
from modules.exploit import Exploiter

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="HoparLFI - Տեղային Ֆայլերի Ներառման (LFI) հայտնաբերման և շահագործման գործիք")
    
    # Թիրախի տարբերակներ
    target_group = parser.add_argument_group("ԹԻՐԱԽԻ ՏԱՐԲԵՐԱԿՆԵՐ")
    target_group.add_argument("-U", dest="url", help="Թեստավորման միակ URL")
    target_group.add_argument("-F", dest="urlfile", help="Բեռնել URL-ների ցուցակ ֆայլից՝ թեստավորման համար")
    target_group.add_argument("-R", dest="reqfile", help="Բեռնել HTTP հարցում ֆայլից՝ թեստավորման համար")
    
    # Հարցման տարբերակներ
    request_group = parser.add_argument_group("ՀԱՐՑՄԱՆ ՏԱՐԲԵՐԱԿՆԵՐ")
    request_group.add_argument("-C", dest="cookie", help="HTTP հարցման Cookie վերնագիր")
    request_group.add_argument("-D", dest="data", help="HTTP հարցման FORM-data")
    request_group.add_argument("-H", dest="header", action="append", help="Լրացուցիչ HTTP վերնագրեր")
    request_group.add_argument("-M", dest="method", default="GET", help="Օգտագործվող HTTP մեթոդ")
    request_group.add_argument("-P", dest="proxy", help="Օգտագործել պրոքսի թիրախին միանալու համար")
    request_group.add_argument("--useragent", help="Օգտագործողի գործակալ (User-Agent)")
    request_group.add_argument("--referer", help="HTTP Referer վերնագիր")
    request_group.add_argument("--placeholder", default="PWN", help="Փոփոխական անուն՝ թեստավորման համար")
    request_group.add_argument("--delay", type=float, default=0, help="Հապաղում հարցումների միջև (միլիվայրկյաններով)")
    request_group.add_argument("--max-timeout", type=int, default=5, help="Սպասման առավելագույն ժամանակ (վայրկյան)")
    request_group.add_argument("--http-ok", type=int, action="append", help="Թույլատրելի HTTP պատասխան կոդ(եր)")
    request_group.add_argument("--csrf-param", help="anti-CSRF թոքեն պարունակող պարամետր")
    request_group.add_argument("--csrf-method", help="CSRF էջ այցելության մեթոդ")
    request_group.add_argument("--csrf-url", help="CSRF թոքեն ստանալու հղում")
    request_group.add_argument("--csrf-data", help="CSRF էջին ուղարկվող POST տվյալներ")
    request_group.add_argument("--second-method", help="Երկրորդական հարցման մեթոդ")
    request_group.add_argument("--second-url", help="Երկրորդական հարցման URL")
    request_group.add_argument("--second-data", help="Երկրորդական հարցման FORM տվյալներ")
    request_group.add_argument("--force-ssl", action="store_true", help="Պարտադրել HTTPS/SSL օգտագործում")
    request_group.add_argument("--no-stop", action="store_true", help="Չկանգնել հայտնաբերումից հետո, շարունակել փորձարկումը")
    
    # Հարձակման մեթոդներ
    attack_group = parser.add_argument_group("ՀԱՐՁԱԿՄԱՆ ՄԵԹՈԴՆԵՐ")
    attack_group.add_argument("-f", "--filter", action="store_true", help="Օգտագործել `filter` փաթեթը հարձակման համար")
    attack_group.add_argument("-i", "--input", action="store_true", help="Օգտագործել `input` փաթեթը հարձակման համար")
    attack_group.add_argument("-d", "--data", action="store_true", help="Օգտագործել `data` փաթեթը հարձակման համար")
    attack_group.add_argument("-e", "--expect", action="store_true", help="Օգտագործել `expect` փաթեթը հարձակման համար")
    attack_group.add_argument("-t", "--trunc", action="store_true", help="Հարձակվել `path traversal` բառապաշարով")
    attack_group.add_argument("-r", "--rfi", action="store_true", help="Հեռակա ֆայլի ներառում (RFI)")
    attack_group.add_argument("-c", "--cmd", action="store_true", help="Հրամանի ներարկում")
    attack_group.add_argument("-file", "--file", action="store_true", help="Օգտագործել `file` փաթեթը")
    attack_group.add_argument("-heur", "--heuristics", action="store_true", help="Թեստեր հիմք ընդունելով հյուրիստիկաները")
    attack_group.add_argument("-a", "--all", action="store_true", help="Օգտագործել բոլոր հասանելի մեթոդները")
    
    # Payload տարբերակներ
    payload_group = parser.add_argument_group("PAYLOAD ՏԱՐԲԵՐԱԿՆԵՐ")
    payload_group.add_argument("-n", choices=['U', 'B'], help="Գործածել payload-ի կոդավորումը՝ URL(U) կամ Base64(B)")
    payload_group.add_argument("-q", "--quick", action="store_true", help="Արագ թեստավորում՝ սահմանափակ payload-ներով")
    payload_group.add_argument("-x", "--exploit", action="store_true", help="Շահագործել և ուղարկել reverse shell եթե RCE կա")
    payload_group.add_argument("--lhost", help="Հոսթ, որին պետք է միանա reverse կապը")
    payload_group.add_argument("--lport", help="Պորտ reverse կապի համար")
    payload_group.add_argument("--callback", help="Callback հղում RFI կամ cmd հայտնաբերման համար")
    
    # Բառապաշարի տարբերակներ
    wordlist_group = parser.add_argument_group("ԲԱՌԱՊԱՇԱՐԻ ՏԱՐԲԵՐԱԿՆԵՐ")
    wordlist_group.add_argument("-wT", dest="wordlist", help="Բառապաշարի ուղի `path traversal` համար")
    wordlist_group.add_argument("--use-long", action="store_true", help="Օգտագործել 'src/wordlists/long.txt'")
    
    # Արդյունքների տարբերակներ
    output_group = parser.add_argument_group("ԱՐԴՅՈՒՆՔՆԵՐԻ ՏԱՐԲԵՐԱԿՆԵՐ")
    output_group.add_argument("--log", help="Պահպանել բոլոր հարցումներն ու պատասխանները ֆայլում")
    
    # Այլ տարբերակներ
    other_group = parser.add_argument_group("ԱՅԼ")
    other_group.add_argument("-v", "--verbose", action="store_true", help="Տպել առավել մանրամասն տեղեկատվություն")

    return parser.parse_args()

def main():
    args = parse_args()
    
    scanner = Scanner(args)
    payload_gen = PayloadGenerator(args)
    exploiter = Exploiter(args)
    
    urls = []
    if args.url:
        urls.append(args.url)
    elif args.urlfile:
        with open(args.urlfile, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    
    techniques = []
    if args.all or args.filter:
        techniques.append("filter")
    if args.all or args.input:
        techniques.append("input")
    if args.all or args.data:
        techniques.append("data")
    if args.all or args.expect:
        techniques.append("expect")
    if args.all or args.trunc:
        techniques.append("trunc")
    if args.all or args.rfi:
        techniques.append("rfi")
    if args.all or args.cmd:
        techniques.append("cmd")
    if args.all or args.file:
        techniques.append("file")
    if args.all or args.heuristics:
        techniques.append("heuristics")
    
    if not techniques:
        print("Սխալ: Պետք է նշվի գոնե մեկ հարձակման մեթոդ")
        return
    
    results = []
    
    for url in urls:
        print(f"Թեստավորվող հղում՝ {url}")
        for technique in techniques:
            payloads = payload_gen.generate(technique)
            for payload in payloads:
                if args.delay:
                    time.sleep(args.delay / 1000.0)
                
                result = scanner.scan(url, technique, payload)
                if result['vulnerable']:
                    print(f"[+] Բացահայտված խոցելիություն՝ {url}, Մեթոդ՝ {technique}, Payload՝ {payload}")
                    results.append(result)
                    
                    if args.exploit and technique in ["rfi", "cmd"]:
                        exploiter.exploit(url, technique, payload)
                    
                    if not args.no_stop:
                        break
                        
                if args.verbose:
                    print(f"Փորձարկված payload՝ {payload}, Վիճակ՝ {result['status']}")
    
    if args.log:
        with open(args.log, 'w') as f:
            json.dump(results, f, indent=2)
    
    os.makedirs("reports", exist_ok=True)
    with open("reports/output.json", 'w') as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()
