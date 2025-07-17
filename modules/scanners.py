import requests
import urllib.parse
import re
from typing import Dict, Optional

class Scanner:
    def __init__(self, args):
        self.args = args
        self.session = requests.Session()
        self.session.timeout = args.max_timeout
        if args.proxy:
            self.session.proxies = {"http": args.proxy, "https": args.proxy}
        if args.useragent:
            self.session.headers["User-Agent"] = args.useragent
        if args.referer:
            self.session.headers["Referer"] = args.referer
        if args.header:
            for header in args.header:
                key, value = header.split(":", 1)
                self.session.headers[key.strip()] = value.strip()
        if args.cookie:
            self.session.headers["Cookie"] = args.cookie
        if args.force_ssl:
            self.base_url = args.url.replace("http://", "https://") if args.url else ""
    
    def scan(self, url: str, technique: str, payload: str) -> Dict:
        try:
            # Prepare request
            method = self.args.method
            data = self.args.data if self.args.data else None
            url = url.replace(self.args.placeholder, urllib.parse.quote(payload))
            
            # Handle CSRF token if specified
            if self.args.csrf_url and self.args.csrf_param:
                csrf_response = self.session.request(
                    self.args.csrf_method or "GET",
                    self.args.csrf_url,
                    data=self.args.csrf_data
                )
                csrf_token = self.extract_csrf_token(csrf_response.text, self.args.csrf_param)
                if data:
                    data[self.args.csrf_param] = csrf_token
            
            # Make request
            response = self.session.request(
                method,
                url,
                data=data,
                timeout=self.args.max_timeout
            )
            
            # Check response
            is_vulnerable = self.check_vulnerability(response, technique, payload)
            
            if not is_vulnerable and "Ֆայլը չի գտնվել" in response.text.lower():
                print(f"ERROR: Ֆայլը չի գտնվել! {url}")
            
            return {
                "url": url,
                "technique": technique,
                "payload": payload,
                "status": response.status_code,
                "vulnerable": is_vulnerable,
                "response_length": len(response.text),
                "response_snippet": response.text[:200]  
            }
        except requests.RequestException as e:
            return {
                "url": url,
                "technique": technique,
                "payload": payload,
                "status": None,
                "vulnerable": False,
                "error": str(e)
            }
    
    def check_vulnerability(self, response: requests.Response, technique: str, payload: str) -> bool:
        if self.args.http_ok and response.status_code not in self.args.http_ok:
            return False
            
        if technique == "trunc":
            patterns = [
                r"root:.*:0:0:",  # Linux /etc/passwd
                r"\[extensions\]",  # Windows win.ini
                r"nobody:.*:",  # Other Linux users
                r"daemon:.*:",  # Common Linux user
                r"www-data:.*:",  # Web server user
                r"for 16-bit app support"  # Windows win.ini
            ]
            return response.status_code == 200 and any(re.search(pattern, response.text) for pattern in patterns)
        elif technique == "filter":
            base64_pattern = r"[A-Za-z0-9+/=]{20,}"  
            return response.status_code == 200 and (
                len(response.text) > 100 or
                re.search(base64_pattern, response.text) or
                "phpinfo" in response.text or
                "<?php" in response.text
            )
        elif technique == "rfi":
            return "remote_file_inclusion_test" in response.text
        elif technique == "cmd":
            return "command_injection_test" in response.text
        return response.status_code == 200 and len(response.text) > 0
    
    def extract_csrf_token(self, text: str, param: str) -> Optional[str]:
        pattern = rf'{param}\s*=\s*[\'"]?([^\'" >]+)[\'"]?'
        match = re.search(pattern, text)
        return match.group(1) if match else None