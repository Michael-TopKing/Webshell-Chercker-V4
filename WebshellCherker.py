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

USER_AGENTS = [ ... ]  # 保持之前的 UA 列表

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
        self.files = {level: open(f"{level.lower()}.txt", 'w', encoding='utf-8') 
                     for level in ["CRITICAL", "HIGH", "SUSPICIOUS"]}

        self.stats = Counter()
        self.last_adjust_time = time.time()
        self.current_global_limit = args.global_limit

    # ... (get_random_headers, safe_url, head_precheck 保持不变)

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

        # === Fingerprint 弱化（关键修复）===
        fp_count = 0
        for fp in CRITICAL_FINGERPRINTS:
            if fp in text_lower or fp in title_lower:
                fp_count += 1
                matched.append(f"FINGERPRINT:{fp}")

        if fp_count >= 1:
            score += 25 * fp_count                    # 从 65 降到 25

        # 危险函数
        php_context = bool(re.search(r'<\?php|<\?', content[:800]))
        critical_count = sum(1 for pattern in self.compiled_regex if pattern.search(content))
        score += critical_count * 28
        if critical_count >= 1:
            matched.append(f"REGEX×{critical_count}")

        # 多特征联合加成（降低单特征误报）
        if critical_count >= 2 and php_context:
            score += 35
            matched.append("MULTI_EXEC_PHP")

        # UI 特征（强信号）
        if "<textarea" in text_lower and any(k in text_lower for k in ["cmd", "exec", "shell", "system"]):
            score += 25
            matched.append("TEXTAREA_CMD")
        if any(x in text_lower for x in ['type="file"', 'upload file', 'file manager', 'uploader']):
            score += 22
            matched.append("UPLOAD_UI")

        # 减误报规则
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

    def is_likely_error_page(self, host: str, content: str) -> bool:
        if len(content) < 350:
            return True
        short_hash = hashlib.md5(content[:2600].encode()).hexdigest()
        self.error_page_hashes[host].append(short_hash)
        # 提高阈值，减少误杀
        return self.error_page_hashes[host].count(short_hash) >= 8

    # producer 使用 streaming 随机化（低内存）
    async def producer(self, queue: asyncio.Queue, directories: List[str], filenames: List[str]):
        dirs = directories[:]
        random.shuffle(dirs)
        for d in dirs:
            fs = filenames[:]
            random.shuffle(fs)
            for f in fs:
                if queue.qsize() > self.args.concurrency * 150:   # 动态控制
                    await asyncio.sleep(0.01)
                await queue.put((d, f))

    # ... run(), worker(), _adaptive_adjust() 等保持合理实现

    def __del__(self):
        for f in self.files.values():
            f.close()

# ====================== 主函数 ======================
def main():
    parser = argparse.ArgumentParser(description="Webshell Detector v7.0 - Balanced & Precise")
    parser.add_argument('--directories', '-d', required=True)
    parser.add_argument('--dictionary', '-w', required=True)
    parser.add_argument('--output', '-o', default='found_webshells.txt')  # 保留兼容
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
