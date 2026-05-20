# 🧠 一、整体定位（这版在安全领域做什么）

👉 这是一个：

 **基于 HTTP 指纹 + 规则评分的 Webshell 远程探测器（Heuristic Scanner）**

用于：

* 扫描大量 URL（目录 × 文件字典）
* 判断是否存在 PHP webshell / 后门
* 输出风险等级（CRITICAL / HIGH / SUSPICIOUS）

# 🔄 二、工作流程（从输入到输出）

整体流程是：

```
目录列表 + 文件字典
        ↓
producer（随机组合生成 URL）
        ↓
async queue（流式调度）
        ↓
worker（并发消费）
        ↓
HTTP GET 请求（aiohttp）
        ↓
过滤层：
    - Content-Type
    - WAF检测
    - error page检测
        ↓
特征分析：
    - fingerprint
    - regex危险函数
    - UI特征
    - PHP context
    - 负向规则（blog/demo）
        ↓
score计算
        ↓
risk分级
        ↓
写入文件（CRITICAL / HIGH / SUSPICIOUS）
        ↓
console输出
```


# 🧩 三、关键模块解析

## 1️⃣ producer（流式生成器）

```python
dirs → shuffle → fs → shuffle → queue.put()
```

### 作用：

* 控制内存
* 避免一次性生成 100万 URL

### 本质：

👉 **lazy URL generator（惰性生成）**


## 2️⃣ queue 调度系统

```python
queue.qsize() > concurrency * 150 → sleep
```

### 作用：

* 防止 producer 过快
* 避免 OOM / backlog explosion


## 3️⃣ 检测核心 calculate_risk()

### 你现在是“三层模型”


### 🧠 Layer 1：Fingerprint（弱化后）

```python
score += 25 * fp_count
```

👉 改进点：

* 从“一票否决” → “累积分数”
* 明显降低误报


### 🧠 Layer 2：行为特征（regex）

```python
system()
exec()
eval()
```

👉 这是**核心危险信号层**


### 🧠 Layer 3：结构特征（UI）

```text
<textarea + cmd
file upload UI
```

👉 这是你现在系统最“值钱”的部分


### 🧠 Layer 4：负向规则（非常重要）

```python
tutorial / blog / demo → score -= 25
```

👉 这是从“检测工具”升级到“分类系统”的关键


# ⚙️ 四、命令行参数说明（argparse）

| 参数                     | 作用             |
| ---------------------- | -------------- |
| -d                     | 目录列表文件         |
| -w                     | 文件字典           |
| -o                     | 输出文件（兼容旧版）     |
| --min-score            | 最低风险阈值         |
| -c                     | 并发 worker 数    |
| --global-limit         | aiohttp 全局并发限制 |
| --disable-error-filter | 关闭误报过滤         |
| --allow-redirect       | 允许 3xx         |


# 📥 五、输入 / 输出示例

## 输入

### directories.txt

```
http://test.com/
http://site.com/admin/
```

### dictionary.txt

```
index.php
shell.php
upload.php
```


## 输出（CRITICAL.txt）

```
http://test.com/shell.php
http://site.com/admin/upload.php
```


## console

```
🚨 [CRITICAL] 92 → http://test.com/shell.php
🚨 [HIGH] 74 → http://site.com/upload.php
```


# ⚡ 六、性能 / 并发机制

## 1️⃣ asyncio + semaphore

```python
global_semaphore
host_semaphores
```

👉 双层限流：

* 控制全局压力
* 防止单 host flood


## 2️⃣ queue-based pipeline

👉 典型 producer-consumer 架构


## 3️⃣ HTTP优化

* keepalive
* connection pooling
* timeout控制
* response size limit


## 4️⃣ adaptive机制（你前面版本延续）

👉 但这版更稳定


# ⚠️ 七、风险分析（真实问题）

## ❗ 1. fingerprint 仍然可能误报

你已经改善了，但仍然：

```
system + PHP context → 75+
```

👉 blog demo 仍可能中招

## ❗ 2. error page hash 仍有边界问题

```python
>= 8 次重复才算 error
```

👉 对 localhost OK
👉 对 CDN / WAF 不稳定


## ❗ 3. queue 控制是 heuristic

不是严格 backpressure

👉 高负载仍可能：

* producer > worker
* 延迟增加


## ❗ 4. 没有真正“语义判断”

仍然是：

```
regex + keyword scoring
```

不是：

```
behavioral / ML detection
```


# 🧪 八、如何部署和使用（一步一步）

## 1️⃣ 安装依赖

```bash
git clone https://github.com/Michael-TopKing/Webshell-Checker-V4.git
cd Webshell-Checker-V4
pip3 install -r requirements.txt
```

## 2️⃣ 准备文件

```
directories.txt
dictionary.txt
```

## 3️⃣ 运行

```bash
python3 WebshellCherker.py \
  -d directories.txt \
  -w dictionary.txt \
  -o found_webshells.txt \
  -c 150
  --min-score 62 \
```

## 4️⃣ 查看结果

```
CRITICAL.txt
HIGH.txt
SUSPICIOUS.txt
```
