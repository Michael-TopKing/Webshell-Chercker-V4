#!/usr/bin/env python3
import argparse
import asyncio
import hashlib
import logging
import random
import re
import time
from collections import defaultdict, deque, Counter
from pathlib import Path
from typing import List, Dict
from urllib.parse import urlparse
import aiohttp

# ====================== 配置 ======================
CRITICAL_FINGERPRINTS = {"wso", "filesman", "b374k", "c99", "r57", "sym", "indoxploit", "madspot", "priv8"}

CRITICAL_REGEX = [
    r"system\s*\(", r"exec\s*\(", r"passthru\s*\(", r"shell_exec\s*\(",
    r"eval\s*\(", r"assert\s*\(", r"base64_decode\s*\(", r"gzinflate\s*\(",
]

ALLOWED_CONTENT_TYPES = {'text/html', 'text/plain', 'application/xhtml+xml'}

MAX_RESPONSE_SIZE = 2_000_000
MAX_HASHES_PER_HOST = 150

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
]


class WebshellDetector:
    def __init__(self, args):
        self.args = args
        self.setup_logging()
        self.session = None
        
        self.global_semaphore = asyncio.Semaphore(args.global_limit)
        self.host_semaphores = defaultdict(lambda: asyncio.Semaphore(4))
        
        self.error_page_hashes = defaultdict(lambda: deque(maxlen=MAX_HASHES_PER_HOST))
        self.compiled_regex = [re.compile(p, re.IGNORECASE) for p in CRITICAL_REGEX]
        self.title_re = re.compile(r'<title>(.*?)</title>', re.I | re.S)
        
        self.seen_urls = set()
        
        # 分级输出文件
        self.files = {
            "CRITICAL": open("critical.txt", 'w', encoding='utf-8'),
            "HIGH": open("high.txt", 'w', encoding='utf-8'),
            "SUSPICIOUS": open("suspicious.txt", 'w', encoding='utf-8'),
        }

        self.stats = Counter()
        self.last_adjust_time = time.time()
        self.current_global_limit = args.global_limit

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s | %(levelname)s | %(message)s',
            handlers=[logging.FileHandler('webshell_detector.log', encoding='utf-8')]
        )
        self.logger = logging.getLogger(__name__)

    async def init_session(self):
        connector = aiohttp.TCPConnector(limit=600, ttl_dns_cache=300, keepalive_timeout=35, ssl=False)
        timeout = aiohttp.ClientTimeout(total=22, connect=12, sock_read=18)
        self.session = aiohttp.ClientSession(timeout=timeout, connector=connector)

    def get_random_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": random.choice(["en-US,en;q=0.9", "zh-CN,zh;q=0.9,en;q=0.8"]),
            "Connection": "keep-alive",
        }

    def safe_url(self, base: str, filename: str) -> str:
        return f"{base.rstrip('/')}/{filename.lstrip('/')}"

    async def head_precheck(self, url: str):
        try:
            async with self.session.head(url, headers=self.get_random_headers(), 
                                       allow_redirects=True, timeout=10) as resp:
                return resp.status in {200, 301, 302, 403}
        except:
            return False

    async def check_url(self, base_url: str, filename: str):
        full_url = self.safe_url(base_url, filename)
        if full_url in self.seen_urls:
            return
        self.seen_urls.add(full_url)

        host = urlparse(full_url).netloc

        async with self.global_semaphore, self.host_semaphores[host]:
            await self.head_precheck(full_url)

            for attempt in range(3):
                try:
                    async with self.session.get(full_url, headers=self.get_random_headers(),
                                              allow_redirects=self.args.allow_redirect) as resp:
                        self.stats[resp.status] += 1

                        ct = resp.headers.get('Content-Type', '').lower()
                        if not any(allowed in ct for allowed in ALLOWED_CONTENT_TYPES):
                            return

                        body = await resp.content.read(MAX_RESPONSE_SIZE + 8192)
                        if len(body) > MAX_RESPONSE_SIZE:
                            return
                        content = body.decode('utf-8', errors='ignore')

                        if self.is_waf_or_blocked(resp.status, content):
                            self._adaptive_adjust()
                            return

                        if not self.args.disable_error_filter:
                            if self.is_likely_error_page(host, content):
                                return

                        title_match = self.title_re.search(content)
                        title = title_match.group(1).strip() if title_match else ""

                        score, risk, matched = self.calculate_risk(content, title)

                        if score >= self.args.min_score:
                            self.save_result(full_url, score, risk, matched, title)

                    self._adaptive_adjust()
                    break

                except (aiohttp.ClientError, asyncio.TimeoutError):
                    self.stats['timeout'] += 1
                    self._adaptive_adjust()
                    if attempt < 2:
                        await asyncio.sleep(random.uniform(0.8, 2.5))
                    continue
                except Exception:
                    break

    def calculate_risk(self, content: str, title: str):
        text_lower = content.lower()
        title_lower = title.lower() if title else ""
        score = 0
        matched = []

        # Fingerprint（弱化）
        fp_count = sum(1 for fp in CRITICAL_FINGERPRINTS if fp in text_lower or fp in title_lower)
        if fp_count >= 1:
            score += 25 * fp_count
            matched.append(f"FINGERPRINT×{fp_count}")

        php_context = bool(re.search(r'<\?php|<\?', content[:800]))
        critical_count = sum(1 for pattern in self.compiled_regex if pattern.search(content))
        score += critical_count * 28
        if critical_count >= 1:
            matched.append(f"REGEX×{critical_count}")

        if critical_count >= 2 and php_context:
            score += 35
            matched.append("MULTI_EXEC_PHP")

        if "<textarea" in text_lower and any(k in text_lower for k in ["cmd", "exec", "shell", "system"]):
            score += 25
            matched.append("TEXTAREA_CMD")
        if any(x in text_lower for x in ['type="file"', 'upload file', 'file manager', 'uploader']):
            score += 22
            matched.append("UPLOAD_UI")

        # 减误报
        if any(word in text_lower for word in ["tutorial", "example", "demo", "blog", "article", "documentation"]):
            score -= 25

        final_score = min(max(int(score), 0), 100)
        
        if final_score >= 80:
            risk = "CRITICAL"
        elif final_score >= 65:
            risk = "HIGH"
        elif final_score >= self.args.min_score:
            risk = "SUSPICIOUS"
        else:
            risk = "LOW"

        return final_score, risk, matched

    def save_result(self, url: str, score: int, risk: str, matched: list, title: str):
        self.files[risk].write(url + "\n")
        self.files[risk].flush()

        color = "\033[1;32m" if risk == "CRITICAL" else "\033[1;33m" if risk == "HIGH" else "\033[1;36m"
        print(f"{color}🚨 [{risk}] {score} → {url}\033[0m")

    def is_waf_or_blocked(self, status: int, content: str) -> bool:
        if status not in {200, 301, 302}:
            return True
        text = content.lower()[:1500]
        signs = ["cloudflare", "cf-ray", "captcha", "sucuri", "attention required"]
        return any(sign in text for sign in signs)

    def is_likely_error_page(self, host: str, content: str) -> bool:
        if len(content) < 350:
            return True
        short_hash = hashlib.md5(content[:2600].encode()).hexdigest()
        self.error_page_hashes[host].append(short_hash)
        return self.error_page_hashes[host].count(short_hash) >= 8

    def _adaptive_adjust(self):
        now = time.time()
        if now - self.last_adjust_time < 8:
            return
        total = sum(self.stats.values())
        if total < 200:
            return

        if self.stats[429] / total > 0.07 or self.stats[403] / total > 0.12:
            self.current_global_limit = max(40, self.current_global_limit - 35)
            self.global_semaphore = asyncio.Semaphore(self.current_global_limit)
            self.logger.warning(f"Adaptive DOWN → {self.current_global_limit}")
        self.last_adjust_time = now
        self.stats.clear()

    async def producer(self, queue: asyncio.Queue, directories: List[str], filenames: List[str]):
        dirs = directories[:]
        random.shuffle(dirs)
        for d in dirs:
            fs = filenames[:]
            random.shuffle(fs)
            for f in fs:
                await queue.put((d, f))

    async def worker(self, queue: asyncio.Queue):
        while True:
            item = None
            try:
                item = await queue.get()
                await self.check_url(*item)
            except asyncio.CancelledError:
                break
            finally:
                if item is not None:
                    queue.task_done()

    async def run(self):
        await self.init_session()
        try:
            directories = self.load_file(self.args.directories)
            filenames = self.load_file(self.args.dictionary)

            total = len(directories) * len(filenames)
            self.logger.info(f"Scan started → {total:,} targets | Min Score: {self.args.min_score}")

            queue: asyncio.Queue = asyncio.Queue(maxsize=15000)
            workers = [asyncio.create_task(self.worker(queue)) for _ in range(self.args.concurrency)]
            producer = asyncio.create_task(self.producer(queue, directories, filenames))

            await producer
            await queue.join()

            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
        finally:
            # 安全关闭文件
            for f in self.files.values():
                f.close()
            if self.session:
                await self.session.close()

    def load_file(self, filepath: str) -> List[str]:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]


def main():
    parser = argparse.ArgumentParser(description="Webshell Detector v7.1 - Fixed & Stable")
    parser.add_argument('--directories', '-d', required=True)
    parser.add_argument('--dictionary', '-w', required=True)
    parser.add_argument('--min-score', type=int, default=62)
    parser.add_argument('--concurrency', '-c', type=int, default=100)
    parser.add_argument('--global-limit', type=int, default=180)
    parser.add_argument('--disable-error-filter', action='store_true')
    parser.add_argument('--allow-redirect', action='store_true')
    args = parser.parse_args()

    detector = WebshellDetector(args)
    asyncio.run(detector.run())


if __name__ == "__main__":
    main()
