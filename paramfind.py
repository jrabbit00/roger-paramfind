#!/usr/bin/env python3
"""
Roger ParamFind - Hidden parameter discovery for bug bounty hunting.
"""

import argparse
import concurrent.futures
import requests
import urllib3
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from difflib import SequenceMatcher
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Wordlists
MINI_WORDLIST = [
    "id", "user", "user_id", "admin", "debug", "test", "lang", "lang_code",
    "page", "limit", "offset", "search", "q", "query", "format", "mode",
    "action", "do", "task", "file", "filename", "path", "dir", "view",
    "theme", "theme_code", "token", "key", "auth", "password", "old_password",
    "new_password", "password_confirm", "email", "role", "status", "type",
    "category", "sort", "order", "by", "start", "end", "date", "from", "to",
    "callback", "cb", "json", "xml", "api", "api_key", "token", "session",
    "redirect", "return", "return_url", "next", "continue", "data", "date",
]

MEDIUM_WORDLIST = [
    # Common parameters
    "id", "user", "user_id", "admin", "debug", "test", "lang", "lang_code",
    "page", "limit", "offset", "search", "q", "query", "format", "mode",
    "action", "do", "task", "file", "filename", "path", "dir", "view",
    "theme", "theme_code", "token", "key", "auth", "password", "old_password",
    "new_password", "password_confirm", "email", "role", "status", "type",
    "category", "sort", "order", "by", "start", "end", "date", "from", "to",
    "callback", "cb", "json", "xml", "api", "api_key", "token", "session",
    "redirect", "return", "return_url", "next", "continue", "data", "date",
    # IDOR related
    "uid", "user_id", "customer_id", "order_id", "product_id", "post_id",
    "article_id", "comment_id", "file_id", "account_id", "member_id",
    "profile_id", "group_id", "team_id", "org_id", "company_id", "invoice_id",
    "transaction_id", "payment_id", "subscription_id", "license_id",
    # Access control
    "admin", "root", "sudo", "access", "privilege", "role", "level", "rank",
    "is_admin", "is_root", "is_superuser", "is_logged_in", "authenticated",
    "authorized", "permission", "capability", "allow", "deny", "grant",
    # Debug/Dev
    "debug", "dev", "development", "test", "testing", "staging", "stage",
    "demo", "sandbox", "preview", "beta", "experimental", "feature", "flags",
    "verbose", "trace", "log", "logging", "error", "errors", "warning",
    # Config
    "config", "configuration", "settings", "preferences", "options",
    "param", "params", "setting", "setup", "init", "initialize", "install",
    # API related
    "api", "api_key", "api_token", "api_secret", "client_id", "client_secret",
    "access_token", "refresh_token", "jwt", "bearer", "authorization",
    "app_id", "app_key", "app_secret", "public_key", "private_key",
    # Payment/Financial
    "amount", "price", "cost", "fee", "total", "subtotal", "tax", "discount",
    "coupon", "promo", "promotion", "currency", "payment", "transaction",
    "invoice", "billing", "card", "credit_card", "account", "routing",
    # File related
    "file", "filename", "name", "path", "dir", "directory", "folder",
    "upload", "download", "attachment", "image", "img", "photo", "document",
    "doc", "pdf", "ext", "extension", "mime", "content_type",
    # User input
    "username", "username", "email", "phone", "address", "city", "country",
    "zip", "zipcode", "postal", "state", "province", "first_name", "last_name",
    "fullname", "name", "age", "birth", "birthday", "gender", "sex",
    # Misc interesting
    "source", "ref", "refer", "referer", "referrer", "origin", "domain",
    "host", "port", "protocol", "ssl", "tls", "version", "v", "ver",
    "platform", "os", "device", "browser", "user_agent", "ua", "ip", "client",
    "latitude", "longitude", "location", "geo", "gps", "timezone", "locale",
    "language", "lang", "encoding", "charset", "content", "body", "text",
    "html", "template", "render", "output", "callback", "handler", "hook",
    "event", "trigger", "schedule", "cron", "job", "queue", "worker",
    "cache", "cached", "expire", "expires", "ttl", "max", "min", "timeout",
]

LARGE_WORDLIST = MEDIUM_WORDLIST + [
    # More parameters
    "id", "user", "name", "title", "desc", "description", "summary", "content",
    "body", "text", "message", "msg", "comment", "note", "notes", "memo",
    "created", "updated", "modified", "deleted", "removed", "expired", "active",
    "enabled", "disabled", "locked", "unlocked", "verified", "approved",
    "pending", "submitted", "published", "draft", "archived", "hidden",
    "visible", "public", "private", "shared", "owner", "creator", "author",
    "editor", "viewer", "commenter", "moderator", "admin", "superadmin",
    "site", "domain", "url", "link", "href", "src", "src_url", "target",
    "width", "height", "size", "length", "count", "number", "num", "page",
    "per_page", "perpage", "items", "results", "rows", "columns", "fields",
    "filter", "filters", "query", "queries", "search", "search_term",
    "term", "keyword", "keywords", "tag", "tags", "label", "labels",
    "group", "groups", "team", "teams", "org", "organization", "company",
    "department", "dept", "division", "business", "industry", "sector",
    "plan", "plans", "subscription", "tier", "level", "package", "bundle",
    "product", "products", "service", "services", "item", "items", "cart",
    "wishlist", "favorites", "bookmarks", "history", "activity", "feed",
    "stream", "timeline", "notifications", "alerts", "updates", "news",
    "blog", "post", "posts", "article", "articles", "page", "pages",
    "news", "new", "event", "events", "calendar", "schedule", "agenda",
    "meeting", "meetings", "appointment", "appointments", "booking",
    "reservation", "ticket", "tickets", "order", "orders", "sale", "sales",
    "deal", "deals", "offer", "offers", "campaign", "campaigns", "promo",
    "promotion", "promotions", "discount", "discounts", "coupon", "coupons",
    "gift", "gifts", "voucher", "vouchers", "reward", "rewards", "points",
    "balance", "credit", "debit", "account", "accounts", "profile", "profiles",
    "settings", "preferences", "config", "configuration", "options",
    "template", "templates", "layout", "layouts", "theme", "themes",
    "style", "styles", "css", "font", "fonts", "color", "colors", "logo",
    "icon", "icons", "image", "images", "photo", "photos", "picture",
    "pictures", "video", "videos", "audio", "music", "sound", "sounds",
    "file", "files", "document", "documents", "doc", "docs", "folder",
    "folders", "directory", "directories", "path", "upload", "download",
    "import", "export", "save", "load", "fetch", "get", "post", "put",
    "patch", "delete", "remove", "add", "create", "edit", "update", "copy",
    "move", "rename", "delete", "archive", "restore", "backup", "restore",
    "sync", "merge", "split", "convert", "encode", "decode", "encrypt",
    "decrypt", "hash", "sign", "verify", "validate", "check", "confirm",
    "submit", "send", "receive", "deliver", "delivered", "read", "unread",
    "seen", "unseen", "open", "closed", "resolved", "pending", "assigned",
    "reassigned", "escalated", "closed", "reopened", "locked", "unlocked",
]


class RogerParamFind:
    def __init__(self, target, wordlist='medium', threads=10, method='GET',
                 data=None, headers=None, cookies=None, quiet=False, 
                 output=None, rate_limit=0):
        self.target = target
        self.wordlist_name = wordlist
        self.threads = threads
        self.method = method
        self.data = data
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.quiet = quiet
        self.output = output
        self.rate_limit = rate_limit
        
        # Load wordlist
        if wordlist == 'mini':
            self.params = MINI_WORDLIST
        elif wordlist == 'large':
            self.params = LARGE_WORDLIST
        else:
            self.params = MEDIUM_WORDLIST
        
        # Try loading from file
        if not self.params:
            try:
                with open(wordlist, 'r') as f:
                    self.params = [line.strip() for line in f if line.strip()]
            except:
                self.params = MEDIUM_WORDLIST
        
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.session.headers.update(headers)
        self.session.cookies.update(cookies)
        
        self.findings = []
        
    def build_url(self, param):
        """Build URL with parameter."""
        parsed = urlparse(self.target)
        query = parse_qs(parsed.query)
        query[param] = 'test'
        
        new_query = urlencode(query, doseq=True)
        new_parsed = parsed._replace(query=new_query)
        return urlunparse(new_parsed)
    
    def check_param(self, param):
        """Check a single parameter."""
        try:
            url = self.build_url(param)
            
            if self.method == 'POST':
                response = self.session.post(
                    url, 
                    data=self.data or {'test': 'value'},
                    timeout=10, 
                    verify=False,
                    allow_redirects=False
                )
            else:
                response = self.session.get(
                    url, 
                    timeout=10, 
                    verify=False,
                    allow_redirects=False
                )
            
            status = response.status_code
            length = len(response.content)
            
            return {
                "param": param,
                "url": url,
                "status": status,
                "length": length,
                "text": response.text[:5000]  # First 5k for comparison
            }
            
        except requests.exceptions.Timeout:
            return {"param": param, "status": "timeout", "error": "Timeout"}
        except requests.exceptions.RequestException as e:
            return {"param": param, "status": "error", "error": str(e)}
    
    def analyze_response(self, original_response, test_response):
        """Analyze if parameter addition caused interesting changes."""
        original = original_response
        test = test_response
        
        # Check status code change
        if original['status'] != test['status']:
            return True, f"Status changed: {original['status']} -> {test['status']}"
        
        # Check content length difference
        length_diff = abs(original['length'] - test['length'])
        if length_diff > 100:
            return True, f"Length changed by {length_diff}"
        
        # Check content similarity
        similarity = SequenceMatcher(None, original.get('text', ''), test.get('text', '')).ratio()
        if similarity < 0.9:
            return True, f"Content similarity: {similarity:.2f}"
        
        return False, ""
    
    def scan(self):
        """Run the parameter scanner."""
        print(f"[*] Starting parameter discovery on: {self.target}")
        print(f"[*] Wordlist: {self.wordlist_name} ({len(self.params)} params)")
        print(f"[*] Method: {self.method}")
        print(f"[*] Threads: {self.threads}")
        print("=" * 60)
        
        # Get baseline response
        try:
            if self.method == 'POST':
                baseline = self.session.post(self.target, data=self.data or {}, timeout=10, verify=False)
            else:
                baseline = self.session.get(self.target, timeout=10, verify=False)
            
            baseline_response = {
                "status": baseline.status_code,
                "length": len(baseline.content),
                "text": baseline.text[:5000]
            }
            print(f"[*] Baseline: {baseline_response['status']} ({baseline_response['length']} bytes)")
        except Exception as e:
            print(f"[!] Error getting baseline: {e}")
            return []
        
        print("[*] Scanning for parameters...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_param, param): param for param in self.params}
            
            for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
                result = future.result()
                
                if result and 'status' in result and isinstance(result['status'], int):
                    is_interesting, reason = self.analyze_response(baseline_response, result)
                    
                    if is_interesting:
                        print(f"[?] {result['param']} - {reason}")
                        self.findings.append({
                            "parameter": result['param'],
                            "url": result['url'],
                            "status": result['status'],
                            "reason": reason
                        })
                    elif not self.quiet:
                        print(f"[{result['status']}] {result['param']}")
                
                if i % 50 == 0:
                    print(f"[*] Progress: {i}/{len(self.params)}")
                
                if self.rate_limit:
                    time.sleep(self.rate_limit)
        
        # Save results
        if self.output:
            with open(self.output, 'w') as f:
                f.write(f"# Parameter Findings for {self.target}\n\n")
                for finding in self.findings:
                    f.write(f"Parameter: {finding['parameter']}\n")
                    f.write(f"URL: {finding['url']}\n")
                    f.write(f"Status: {finding['status']}\n")
                    f.write(f"Reason: {finding['reason']}\n\n")
        
        print()
        print("=" * 60)
        print(f"[*] Scan complete!")
        print(f"[*] Parameters tested: {len(self.params)}")
        print(f"[*] Interesting findings: {len(self.findings)}")
        
        if self.findings:
            print("\n[+] Results:")
            for f in self.findings:
                print(f"  {f['parameter']} ({f['status']}) - {f['reason']}")
        
        return self.findings


def main():
    parser = argparse.ArgumentParser(
        description="Roger ParamFind - Hidden parameter discovery for bug bounty hunting"
    )
    parser.add_argument("target", help="Target URL (e.g., https://target.com/page)")
    parser.add_argument("-w", "--wordlist", default="medium", help="Wordlist (mini/medium/large or file path)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("-m", "--method", default="GET", help="HTTP method (GET/POST)")
    parser.add_argument("-d", "--data", help="POST data")
    parser.add_argument("-H", "--headers", help="Custom headers (JSON)")
    parser.add_argument("-c", "--cookies", help="Cookies (JSON)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("-o", "--output", help="Output results to file")
    parser.add_argument("-r", "--rate-limit", type=float, default=0, help="Rate limit (seconds)")
    
    args = parser.parse_args()
    
    # Parse headers/cookies
    headers = {}
    cookies = {}
    if args.headers:
        import json
        try:
            headers = json.loads(args.headers)
        except:
            print("[!] Invalid headers JSON")
    if args.cookies:
        import json
        try:
            cookies = json.loads(args.cookies)
        except:
            print("[!] Invalid cookies JSON")
    
    scanner = RogerParamFind(
        target=args.target,
        wordlist=args.wordlist,
        threads=args.threads,
        method=args.method,
        data=args.data,
        headers=headers,
        cookies=cookies,
        quiet=args.quiet,
        output=args.output,
        rate_limit=args.rate_limit
    )
    
    scanner.scan()


if __name__ == "__main__":
    main()