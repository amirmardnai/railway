"""
پنل مدیریت XRAY — Ultimate Edition + CPU/RAM Optimized
"""
import os, json, uuid, asyncio, hashlib, secrets, time, subprocess, re, base64, ipaddress, shutil
from datetime import datetime, timedelta
from collections import deque
from typing import Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response, HTTPException, Cookie, APIRouter
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, PlainTextResponse
import httpx, uvicorn

# ── تنظیمات ──────────────────────────────────────────────
PORT         = 5000
ADMIN_PASS   = os.environ.get("ADMIN_PASSWORD", "admin1234")
ADMIN_PATH   = os.environ.get("ADMIN_PATH", "panel").strip("/")
PUBLIC_HOST  = os.environ.get("PUBLIC_HOST", "")
MASTER_UUID  = os.environ.get("UUID", "90cd4a77-141a-43c9-991b-08263cfe9c10")
LINKS_FILE   = "/app/links.json"
CFG_FILE     = "/app/cfg.json"
XRAY_LOG     = "/tmp/xray_access.log"
NGINX_LOG    = "/tmp/nginx_access.log"
STATS_FILE   = "/app/stats.json"
XRAY_API_PORT = 10085

# تنها پروتکل پشتیبانی‌شده: VLESS + WS + TLS. همهٔ پروتکل‌های دیگر (XHTTP/gRPC/HTTPUpgrade/Trojan/VMess/Reality)
# حذف شده‌اند تا مصرف رم به‌ازای هر کاربر ~۸ برابر کمتر شود (قبلاً هر کاربر در ۸ inbound ثبت می‌شد) و
# سرور با ۱۰۰+ کاربر هم‌زمان OOM نشود.
XRAY_WS_PORT = 18080

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
ADMIN_CHAT_ID = os.environ.get("ADMIN_CHAT_ID", "")

# توکن API ریلوی برای خواندن متریک‌های واقعی (رم/ترافیک/دیسک) از خود ریلوی.
# باید دستی در Variables پروژه ست شود: یک توکن از railway.com/account/tokens بسازید و به نام RAILWAY_API_TOKEN ست کنید.
# بقیه مقادیر (PROJECT_ID/ENVIRONMENT_ID/SERVICE_ID) را خود ریلوی به‌صورت خودکار در اختیار کانتینر می‌گذارد.
RAILWAY_API_TOKEN = os.environ.get("RAILWAY_API_TOKEN", "").strip()
RAILWAY_PROJECT_ID = os.environ.get("RAILWAY_PROJECT_ID", "").strip()
RAILWAY_ENVIRONMENT_ID = os.environ.get("RAILWAY_ENVIRONMENT_ID", "").strip()
RAILWAY_SERVICE_ID = os.environ.get("RAILWAY_SERVICE_ID", "").strip()
RAILWAY_GRAPHQL_URL = "https://backboard.railway.com/graphql/v2"

PASS_HASH = hashlib.sha256(ADMIN_PASS.encode()).hexdigest()

# ── state ─────────────────────────────────────────────────
SESSIONS = {}
LINKS = {}
error_log = deque(maxlen=50)
stats = {"bytes": 0, "bytes_prev": 0, "bytes_prev_time": time.time(), "dl_speed": 0, "ul_speed": 0, "start": time.time(),
         # شمارنده‌های مجزای دانلود/آپلود از خود Xray (برای محاسبهٔ سرعت واقعی به‌جای تخمین ساختگی ۶۵/۳۵)
         "down_bytes": 0, "up_bytes": 0, "down_prev": 0, "up_prev": 0}
sys_info = {"ram": 0, "cpu": 0, "cpu_cores": 0, "disk_used_gb": 0, "disk_total_gb": 0, "disk_pct": 0, "ram_used_mb": 0, "ram_limit_mb": 0}
prev_cpu = None
_prev_cpu_usage = None  # (usage_usec, wall_time) برای محاسبهٔ CPU واقعی کانتینر از cgroup
_cg_base_cache = None   # مسیر پایهٔ cgroup v2 (یک‌بار حل می‌شود)
xray_process = None
xray_log_pos = 0
nginx_log_pos = 0
user_traffic = {}
user_last_active = {}       # uid -> last_seen   کاربران آنلاین (از شمارندهٔ ترافیک + لاگ Xray)
ws_connections = {}        # ip -> last_seen   مجموعهٔ ایپی‌های واقعی فعال روی /ws (برای شمارش دقیق ایپی آنلاین)
protocol_connections = {}  # protocol -> {ip: last_seen}  ایپی واقعی هر پروتکل از لاگ Nginx
user_protocol_active = {}  # uid -> {protocol: last_seen}  کدام کاربر به کدام پروتکل وصل است
inbound_last_active = {}   # tag -> last_seen   آیا همین الان ترافیک از این inbound رد شده (مستقل از تشخیص ایپی)
total_unique_ips = set()
# شمارش دقیق اتصالات هم‌زمان مستقیماً از stub_status نگینکس (نه تخمین) — هر ۵ ثانیه آپدیت می‌شود.
net_info = {"active": 0, "reading": 0, "writing": 0, "waiting": 0}
# کش متریک‌های ریلوی؛ هر ۶۰ ثانیه یک‌بار آپدیت می‌شود (سبک، تا فشاری به رم/CPU وارد نشود)
railway_metrics = {"available": False, "ram_pct": 0, "mem_used_gb": 0, "mem_limit_gb": 0,
                    "net_bytes": 0, "net_rx_gb": 0, "net_tx_gb": 0,
                    "disk_used_gb": 0, "disk_limit_gb": 0, "disk_pct": 0, "updated": 0,
                    "net_rx_total_gb": 0, "net_tx_total_gb": 0, "net_rx_last_ts": 0, "net_tx_last_ts": 0}

RATE_LIMITS = {}
tg_client = None
WEBHOOK_SECRET = secrets.token_urlsafe(24)  # برای تایید اینکه درخواست واقعا از تلگرام می‌آید

# تنها یک پروتکل پشتیبانی می‌شود: VLESS + WS + TLS.
PROTOCOL_LABELS = {"ws": "VLESS + WS + TLS"}
# تگ inbound در کانفیگ Xray -> نام پروتکل (برای تشخیص آنلاین بودن کانفیگ از شمارندهٔ inbound خود Xray)
TAG_TO_PROTO = {"ws-in": "ws"}
PROTO_TO_TAG = {v: k for k, v in TAG_TO_PROTO.items()}  # reverse: proto -> tag
CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")  # RFC 6598 - Shared/CGNAT Address Space (یک‌بار ساخته می‌شود، نه هر بار)

# فرمت لاگ Xray بسته به نسخه فرق دارد:
#   نسخه‌های جدید:    from tcp:1.2.3.4:5678 accepted tcp:dest:443 [reality-in -> direct] email: <uuid>
#   نسخه‌های قدیمی‌تر: from 1.2.3.4:5678 accepted tcp:dest:443 [reality-in -> direct] email: <uuid>
# پیشوند "tcp:" قبل از ایپی اختیاری گرفته می‌شود، و تگ inbound داخل [] هم استخراج می‌شود تا
# بشود فقط روی reality-in فیلتر کرد (نه هر خط دیگری که به اشتباه ایپی غیر-لوکال داشته باشد).
XRAY_RE = re.compile(
    r'from\s+(?:tcp:)?([\d.a-fA-F:]+):\d+\s+accepted\s+\S+\s+\[([\w\-]+)\s*->[^\]]*\]\s*email:\s*'
    r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',
    re.IGNORECASE
)

def log_err(msg):
    error_log.append({"e": msg, "t": datetime.now().isoformat()})

def is_public_ip(ip: str) -> bool:
    """فقط ایپی واقعی کاربر را قبول می‌کند؛ ایپی‌های داخلی/لوکال/CGNAT (مثل 100.64.x.x که اینفرا داخلی هاست استفاده می‌کند) رد می‌شوند."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return False
    if addr.version == 4 and addr in CGNAT_NET:
        return False
    return True

def rate_limiter(ip: str, action: str, limit: int = 5, timeframe: int = 10):
    now = time.time()
    # پاکسازی واقعی entryهای قدیمی (به‌جای پاک کردن کامل دیکشنری وقتی به ۲۰۰ آیپی می‌رسد).
    # نکته مهم دربارهٔ نسخهٔ قبلی: RATE_LIMITS.clear() کل تاریخچهٔ rate-limit همهٔ آیپی‌ها را
    # یکجا پاک می‌کرد، نه فقط آیپی‌های قدیمی — یعنی با ۱۰۰+ کاربر (که خیلی‌هاشان پشت یک
    # CGNAT/NAT مشترک هستند و آیپی محدودی دارند) به‌محض رسیدن به ۲۰۰ کلید، تمام rate-limitها
    # یکجا ریست می‌شد و عملاً محافظت بی‌اثر می‌شد. اینجا فقط actionهایی که در timeframe خودشان
    # دیگر هیچ timestamp فعالی ندارند حذف می‌شوند، و رشد دیکشنری واقعاً محدود می‌ماند.
    if len(RATE_LIMITS) > 200:
        for k in list(RATE_LIMITS.keys()):
            for a in list(RATE_LIMITS[k].keys()):
                RATE_LIMITS[k][a] = [t for t in RATE_LIMITS[k][a] if now - t < timeframe]
                if not RATE_LIMITS[k][a]: del RATE_LIMITS[k][a]
            if not RATE_LIMITS[k]: del RATE_LIMITS[k]

    if ip not in RATE_LIMITS: RATE_LIMITS[ip] = {}
    if action not in RATE_LIMITS[ip]: RATE_LIMITS[ip][action] = []
    RATE_LIMITS[ip][action] = [t for t in RATE_LIMITS[ip][action] if now - t < timeframe]
    if len(RATE_LIMITS[ip][action]) >= limit: return False
    RATE_LIMITS[ip][action].append(now)
    return True

def sanitize_label(label: str) -> str:
    return re.sub(r'[^\w\s\-@.]', '', label)[:30]

# ── System Info (RAM/CPU) ────────────────────────────────
def _read_stat_field(path, field):
    """یک فیلد خاص را از فایل‌های stat سبک cgroup می‌خواند (مثل inactive_file / usage_usec)."""
    try:
        with open(path) as f:
            for line in f:
                if line.startswith(field + " "):
                    return int(line.split()[1])
    except Exception:
        pass
    return 0

def _cgroup_v2_base():
    """
    مسیر پایهٔ cgroup v2 *همین پروسه* را برمی‌گرداند.
    نکتهٔ کلیدی: در داکر/ریلوی پروسه معمولاً در یک cgroup تو‌در‌تو (مثل /user) قرار دارد،
    نه در ریشهٔ /sys/fs/cgroup. کد قبلی از ریشه می‌خواند که آنجا memory.current خالی بود و
    به همین خاطر به /proc/meminfo (رم کل ماشین) برمی‌گشت. اینجا مسیر واقعی را از
    /proc/self/cgroup حل می‌کنیم تا متریک‌های *خود کانتینر* خوانده شوند.
    """
    global _cg_base_cache
    if _cg_base_cache is not None:
        return _cg_base_cache or None
    base = ""
    try:
        with open("/proc/self/cgroup") as f:
            for line in f:
                parts = line.strip().split(":", 2)
                # cgroup v2 یک خط دارد:  0::/some/nested/path
                if len(parts) == 3 and parts[0] == "0":
                    rel = parts[2] or "/"
                    cand = "/sys/fs/cgroup" + rel
                    if os.path.exists(os.path.join(cand, "memory.current")) or \
                       os.path.exists(os.path.join(cand, "cpu.stat")):
                        base = cand
                    break
    except Exception:
        pass
    if not base:
        # fallback: ریشه (وقتی پروسه واقعاً در ریشه است)
        if os.path.exists("/sys/fs/cgroup/memory.current") or os.path.exists("/sys/fs/cgroup/cpu.stat"):
            base = "/sys/fs/cgroup"
    _cg_base_cache = base
    return base or None

def _count_cpuset(base):
    """تعداد هسته‌های مجاز کانتینر را از cpuset.cpus.effective می‌شمارد (مثل '0-1' یا '0,2-3')."""
    for name in ("cpuset.cpus.effective", "cpuset.cpus"):
        try:
            raw = open(os.path.join(base, name)).read().strip()
            if not raw:
                continue
            n = 0
            for part in raw.split(","):
                if "-" in part:
                    a, b = part.split("-"); n += int(b) - int(a) + 1
                else:
                    n += 1
            if n > 0:
                return n
        except Exception:
            continue
    return 0

def get_cgroup_mem():
    """
    رم *واقعی کانتینر* را از cgroup خودِ پروسه می‌خواند (مسیر تو‌در‌تو را درست حل می‌کند).
    این همان عددی است که کرنل برای OOM-kill استفاده می‌کند و با چیزی که در داشبورد ریلوی
    می‌بینید یکی است؛ برخلاف /proc/meminfo که رم کل ماشین فیزیکی را نشان می‌داد (فیک).
    خروجی: (used_bytes, limit_bytes) یا None اگر هیچ محدودیت cgroup واقعی پیدا نشد.
    """
    base = _cgroup_v2_base()
    # cgroup v2 (مسیر صحیحِ تو‌در‌تو)
    if base:
        try:
            cur_path = os.path.join(base, "memory.current")
            max_path = os.path.join(base, "memory.max")
            if os.path.exists(cur_path) and os.path.exists(max_path):
                cur_raw = open(cur_path).read().strip()
                limit_raw = open(max_path).read().strip()
                if cur_raw and limit_raw and limit_raw != "max":
                    used = int(cur_raw); limit = int(limit_raw)
                    # کشِ قابل‌بازیابی (inactive_file) را کم می‌کنیم تا فقط مصرف «واقعی» بماند
                    # (همان منطقی که docker stats / cAdvisor استفاده می‌کنند)
                    inactive_file = _read_stat_field(os.path.join(base, "memory.stat"), "inactive_file")
                    used_real = max(0, used - inactive_file)
                    if limit > 0:
                        return used_real, limit
        except Exception:
            pass
    # cgroup v1 (fallback برای هاست‌های قدیمی‌تر)
    try:
        cur_path = "/sys/fs/cgroup/memory/memory.usage_in_bytes"
        max_path = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
        if os.path.exists(cur_path) and os.path.exists(max_path):
            used = int(open(cur_path).read().strip())
            limit = int(open(max_path).read().strip())
            # اگر limit واقعی ست نشده باشد یک عدد بسیار بزرگ (تقریباً unlimited) برمی‌گردد
            if 0 < limit < 10 ** 14:
                inactive_file = _read_stat_field("/sys/fs/cgroup/memory/memory.stat", "total_inactive_file")
                return max(0, used - inactive_file), limit
    except Exception:
        pass
    return None

def get_cgroup_cpu():
    """
    CPU *واقعی همین کانتینر* را از cgroup می‌خواند و به‌صورت درصدِ سهمِ کانتینر برمی‌گرداند.
    کد قبلی CPU را از /proc/stat می‌خواند که مصرف کل ماشین میزبان ریلوی (همهٔ کانتینرها) بود
    و عملاً فیک/ثابت به‌نظر می‌رسید. اینجا usage_usec را از cpu.stat می‌خوانیم و دلتای آن را
    نسبت به زمانِ سپری‌شده و تعداد هسته‌های اختصاص‌یافته حساب می‌کنیم.
    خروجی: (cpu_pct, cores) یا None اگر cgroup در دسترس نبود.
    """
    global _prev_cpu_usage
    base = _cgroup_v2_base()
    if not base:
        return None
    stat_path = os.path.join(base, "cpu.stat")
    if not os.path.exists(stat_path):
        return None
    usage = _read_stat_field(stat_path, "usage_usec")  # میکروثانیهٔ تجمعی مصرف CPU
    if usage <= 0:
        return None
    # تعداد هسته‌ها: اول از quota در cpu.max، اگر unlimited بود از cpuset، در نهایت os.cpu_count
    cores = 0.0
    try:
        cm = open(os.path.join(base, "cpu.max")).read().strip().split()
        if cm and cm[0] != "max":
            quota = float(cm[0]); period = float(cm[1]) if len(cm) > 1 else 100000.0
            if period > 0:
                cores = quota / period           # مثلا 200000/100000 = 2.0 هسته
    except Exception:
        pass
    if cores <= 0:
        cores = float(_count_cpuset(base)) or float(os.cpu_count() or 1)
    now = time.time()
    pct = 0
    if _prev_cpu_usage is not None:
        d_usage = usage - _prev_cpu_usage[0]         # میکروثانیهٔ مصرف‌شده در بازه
        d_wall = now - _prev_cpu_usage[1]            # ثانیهٔ سپری‌شده (دیوار)
        if d_wall > 0 and cores > 0:
            pct = (d_usage / (d_wall * 1e6 * cores)) * 100.0
            pct = max(0, min(100, int(round(pct))))
    _prev_cpu_usage = (usage, now)
    cores_disp = int(cores) if abs(cores - round(cores)) < 0.05 else round(cores, 1)
    return pct, cores_disp

def get_sys_info():
    global prev_cpu
    try:
        # ── RAM (سهم واقعی کانتینر از cgroup) ──
        cg = get_cgroup_mem()
        if cg:
            used, limit = cg
            sys_info["ram"] = int(used / limit * 100) if limit else 0
            sys_info["ram_used_mb"] = round(used / (1024 ** 2), 1)
            sys_info["ram_limit_mb"] = round(limit / (1024 ** 2), 1)
        else:
            # fallback: خارج از کانتینر (اجرای محلی) — رم کل ماشین
            with open('/proc/meminfo', 'r') as f:
                meminfo = {}
                for line in f:
                    parts = line.split(':')
                    if len(parts) == 2:
                        try: meminfo[parts[0].strip()] = int(parts[1].strip().split(' ')[0])
                        except: pass
            total = meminfo.get('MemTotal', 0)
            available = meminfo.get('MemAvailable', 0)
            if total > 0: sys_info["ram"] = int(((total - available) / total) * 100)
            sys_info["ram_used_mb"] = round((total - available) / 1024, 1) if total else 0
            sys_info["ram_limit_mb"] = round(total / 1024, 1) if total else 0

        # ── CPU (سهم واقعی کانتینر از cgroup؛ نه کل ماشین میزبان) ──
        cc = get_cgroup_cpu()
        if cc is not None:
            sys_info["cpu"], sys_info["cpu_cores"] = cc
        else:
            # fallback: /proc/stat (فقط وقتی cgroup در دسترس نیست — مثل اجرای محلی خارج کانتینر)
            with open('/proc/stat', 'r') as f:
                parts = f.readline().split()[1:]
                parts = [int(x) for x in parts]
                idle = parts[3] + (parts[4] if len(parts)>4 else 0)
                total = sum(parts)
                if prev_cpu is None: prev_cpu = (idle, total)
                else:
                    prev_idle, prev_total = prev_cpu
                    delta_idle = idle - prev_idle
                    delta_total = total - prev_total
                    if delta_total > 0: sys_info["cpu"] = max(0, int(100 - (100 * delta_idle / delta_total)))
                    prev_cpu = (idle, total)
            if not sys_info.get("cpu_cores"):
                sys_info["cpu_cores"] = os.cpu_count() or 1

        # ── Disk: مستقیماً از خود فایل‌سیستم کانتینر خوانده می‌شود (نه از API ریلوی) ──
        try:
            du = shutil.disk_usage("/")
            sys_info["disk_total_gb"] = round(du.total / (1024 ** 3), 2)
            sys_info["disk_used_gb"] = round(du.used / (1024 ** 3), 2)
            sys_info["disk_pct"] = round(du.used / du.total * 100, 1) if du.total else 0
        except: pass
    except: pass

# ── Xray Core Manager ────────────────────────────────────
def load_data():
    global LINKS, total_unique_ips, user_traffic, stats
    try:
        if os.path.exists(LINKS_FILE):
            with open(LINKS_FILE, "r") as f: LINKS = json.load(f)
    except: LINKS = {}
    try:
        if os.path.exists(STATS_FILE):
            with open(STATS_FILE, "r") as f:
                data = json.load(f)
                total_unique_ips = set(data.get("total_unique_ips", []))
                stats["bytes"] = data.get("bytes", 0)
                stats["start"] = data.get("start", time.time())
                user_traffic = data.get("user_traffic", {})
                if "railway_net_rx_total_gb" in data:
                    railway_metrics["net_rx_total_gb"] = data.get("railway_net_rx_total_gb", 0)
                    railway_metrics["net_tx_total_gb"] = data.get("railway_net_tx_total_gb", 0)
                    railway_metrics["net_rx_last_ts"] = data.get("railway_net_rx_last_ts", 0)
                    railway_metrics["net_tx_last_ts"] = data.get("railway_net_tx_last_ts", 0)
    except: pass

    updated = False
    for uid, info in LINKS.items():
        if "short_id" not in info: info["short_id"] = secrets.token_hex(4)[:7]; updated = True
        if "clean_ip" not in info: info["clean_ip"] = ""; updated = True
    if updated: save_links()

def save_links():
    # نکته مهم: save_links حالا می‌تواند هم از thread اصلی (event loop) و هم از داخل
    # sync_xray_config در یک executor thread جدا صدا زده شود. json.dump از دیکشنری LINKS
    # مستقیماً پیمایش می‌کند؛ اگر هم‌زمان thread دیگری یک کلید اضافه/حذف کند (create_link/delete_link)
    # ممکن است RuntimeError بدهد. dict(LINKS) یک کپی سطحی فوری و atomic (تحت GIL) می‌گیرد.
    with open(LINKS_FILE, "w") as f: json.dump(dict(LINKS), f)

def save_stats():
    # نکته مهم: این تابع حالا معمولاً از طریق save_stats_async در یک executor thread جدا اجرا
    # می‌شود، درحالی‌که event loop اصلی (stats_updater و سایر endpointها) هم‌زمان می‌توانند
    # user_traffic را آپدیت کنند یا به total_unique_ips آیپی اضافه کنند. list(...)/dict(...)
    # اینجا یک snapshot فوری (atomic زیر GIL) می‌گیرند تا پیمایش وسط تغییر اندازه به خطا نخورد.
    total_ips_snapshot = list(total_unique_ips)
    user_traffic_snapshot = dict(user_traffic)
    with open(STATS_FILE, "w") as f:
        json.dump({
            "total_unique_ips": total_ips_snapshot, "bytes": stats["bytes"], "start": stats["start"],
            "user_traffic": user_traffic_snapshot,
            "railway_net_rx_total_gb": railway_metrics.get("net_rx_total_gb", 0),
            "railway_net_tx_total_gb": railway_metrics.get("net_tx_total_gb", 0),
            "railway_net_rx_last_ts": railway_metrics.get("net_rx_last_ts", 0),
            "railway_net_tx_last_ts": railway_metrics.get("net_tx_last_ts", 0),
        }, f)

async def save_stats_async():
    """
    نسخهٔ async برای فراخوانی از داخل event loop (مثلاً stats_updater).
    save_stats() معمولی نوشتن فایل سینک (بلاکینگ دیسک I/O) است؛ هر بار که از داخل
    یک کوروتین صدا زده می‌شد، با user_traffic بزرگ (۱۰۰ کاربر) برای چند میلی‌ثانیه
    event loop را قفل می‌کرد. اینجا با run_in_executor به یک thread جدا منتقل می‌شود
    تا هندل کردن ریکوئست‌های HTTP هم‌زمان معطل نماند.
    """
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, save_stats)

def get_xray_env():
    """
    Xray-core با Go نوشته شده؛ به‌صورت پیش‌فرض Go اجازه می‌دهد heap تا حدی بزرگ شود که
    خودش صلاح می‌داند (می‌تواند چند برابر دادهٔ زنده باشد) — این یکی از دلایل اصلی است که
    با ۱۰۰+ کاربر هم‌زمان، رم به‌سرعت بالا می‌رود و کانتینر OOM می‌شود.
    با GOMEMLIMIT (یک سقف نرم برای heap، از Go 1.19 به بعد) به Go می‌گوییم خودش را به
    درصدی از سقف *واقعی* همین کانتینر (که از cgroup خوانده می‌شود) محدود کند، و با GOGC
    پایین‌تر، garbage collector را تهاجمی‌تر می‌کنیم (کمی CPU بیشتر، رم پایدار کمتر).
    """
    env = os.environ.copy()
    cg = get_cgroup_mem()
    if cg:
        _, limit = cg
        # حدود ۵۰٪ از سقف رم کانتینر به Xray اختصاص می‌دهیم (نه ۶۰٪)، و یک سقف مطلق ۳۰۰ مگابایت
        # هم می‌گذاریم — چون ریلوی بین ۵۱۲ مگابایت تا ۱ گیگابایت نوسان می‌کند و باید حتی در حالت
        # سقف بالاتر هم برای Nginx (۲ worker) + پنل پایتون + سیستم جا کافی باقی بماند.
        xray_mem_cap = min(int(limit * 0.5), 300 * 1024 * 1024)
        if xray_mem_cap > 64 * 1024 * 1024:  # کمتر از این عدد بی‌معنی است
            env["GOMEMLIMIT"] = str(xray_mem_cap)
    env.setdefault("GOGC", "50")
    return env

# ── مدیریت هات کاربر از طریق Xray API (بدون kill/spawn پروسه) ───────────────
# با adu/rmu کاربر اضافه/حذف می‌شود و هیچ اتصال فعالی قطع نمی‌شود. این جایگزین
# ری‌استارت کامل Xray می‌شود که قبلاً با هر تغییر کاربر، *همهٔ* کاربران را قطع می‌کرد.
def make_inbound_templates():
    """قالب inbound بدون client. تنها یک inbound: VLESS + WS روی مسیر /ws.
    مشترک بین sync کامل و افزودن هات کاربر تا از واگرایی تنظیمات جلوگیری شود."""
    return [
        {"port": XRAY_WS_PORT, "listen": "127.0.0.1", "protocol": "vless", "tag": "ws-in", "settings": {"clients": [], "decryption": "none"}, "streamSettings": {"network": "ws", "wsSettings": {"path": "/ws"}}},
    ]

def _client_for_inbound(uid):
    """آبجکت client برای VLESS."""
    return {"id": uid, "level": 0, "email": uid}

def _xray_api(args, timeout=4):
    """فراخوانی sync به xray api. خروجی: (rc, stdout, stderr)."""
    try:
        r = subprocess.run(["/usr/local/bin/xray", "api", args[0], f"--server=127.0.0.1:{XRAY_API_PORT}", *args[1:]],
                           capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return -1, "", str(e)

def add_user_hot(uid):
    """افزودن کاربر به inbound بدون ری‌استارت. True اگر موفق."""
    templates = make_inbound_templates()
    for inb in templates:
        inb["settings"]["clients"] = [_client_for_inbound(uid)]
    tmp = f"/tmp/_adu_{uid}.json"
    try:
        with open(tmp, "w") as f:
            json.dump({"inbounds": templates}, f)
        rc, out, err = _xray_api(["adu", tmp], timeout=5)
        return rc == 0
    except Exception:
        return False
    finally:
        try: os.remove(tmp)
        except Exception: pass

def remove_user_hot(uid):
    """حذف کاربر از inbound بدون ری‌استارت (idempotent؛ اگر نباشد هم خطا نمی‌دهد)."""
    for inb in make_inbound_templates():
        _xray_api(["rmu", f"-tag={inb['tag']}", uid], timeout=4)
    return True

def ensure_user_hot(uid):
    """تضمین حضور کاربر با تنظیمات تازه (برای edit/extend/reset): اول حذف، بعد افزودن تا adu قطعاً موفق شود."""
    remove_user_hot(uid)
    return add_user_hot(uid)

async def add_user_hot_async(uid):
    return await asyncio.get_running_loop().run_in_executor(None, add_user_hot, uid)

async def remove_user_hot_async(uid):
    return await asyncio.get_running_loop().run_in_executor(None, remove_user_hot, uid)

async def ensure_user_hot_async(uid):
    return await asyncio.get_running_loop().run_in_executor(None, ensure_user_hot, uid)

def sync_xray_config():
    global xray_process

    active_links = {}
    # نکته مهم: این تابع حالا از طریق sync_xray_config_async در یک thread جدا (executor) اجرا می‌شود،
    # درحالی‌که event loop اصلی هم‌زمان می‌تواند LINKS را تغییر دهد (مثلاً create_link/delete_link).
    # list(...) اینجا یک snapshot فوری از items می‌گیرد تا اگر دیکشنری وسط پیمایش توسط thread دیگری
    # تغییر اندازه دهد، خطای «dictionary changed size during iteration» رخ ندهد.
    for uid, info in list(LINKS.items()):
        if info.get("status") in ["expired", "blocked"]: continue
        if info.get("expiry_time") and time.time() > info["expiry_time"]:
            info["status"] = "expired"; continue
        if info.get("data_limit") and user_traffic.get(uid, 0) >= info["data_limit"]:
            info["status"] = "expired"; continue
        active_links[uid] = info

    save_links()

    # ساخت inbound از قالب مشترک (همان قالبی که افزودن هات کاربر استفاده می‌کند).
    inbounds = make_inbound_templates()
    for _inb in inbounds:
        _inb["settings"]["clients"] = [_client_for_inbound(_uid) for _uid in active_links.keys()]
    
    cfg = {
        "log": {"loglevel": "info", "access": XRAY_LOG}, 
        "stats": {},
        "policy": {
            # تنظیمات زیر برای جلوگیری از مصرف بی‌رویه رم وقتی تعداد زیادی کاربر هم‌زمان وصل می‌شوند اضافه شده:
            # connIdle از ۶۰ به ۳۰۰ ثانیه: اتصالات بی‌کار زودهنگام بسته نشوند (علت اصلی «قط‌وصل» بدون
            #   ری‌استارت در تعداد بالا). مصرف رم حالا با GOMEMLIMIT/cgroup کنترل می‌شود، پس این تریدآف ارزشش را دارد.
            # handshake از ۴ به ۸ ثانیه: زیر بار CPU بالا، هندشیک TLS گاهی >۴ ثانیه می‌شد و اتصال شکست می‌خورد
            #   (کاربر دوباره وصل می‌شد = قط‌وصل). ۸ ثانیه فضای کافی می‌دهد.
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True,
                              "handshake": 8, "connIdle": 300, "uplinkOnly": 2, "downlinkOnly": 4,
                              "bufferSize": 32}},
            "system": {"statsInboundUplink": True, "statsInboundDownlink": True}
        },
        "api": {"tag": "api_service", "services": ["HandlerService", "LoggerService", "StatsService"]},
        "inbounds": [{"listen": "127.0.0.1", "port": XRAY_API_PORT, "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}, "tag": "api_in"}, *inbounds],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
            {"protocol": "freedom", "tag": "api_service"}
        ],
        "routing": {"rules": [{"type": "field", "inboundTag": ["api_in"], "outboundTag": "api_service"}]}
    }
    
    with open(CFG_FILE, "w") as f: json.dump(cfg, f, indent=2)
    try:
        if xray_process:
            xray_process.terminate()
            try: xray_process.wait(timeout=2)
            except: xray_process.kill()
        if os.path.exists(XRAY_LOG): os.remove(XRAY_LOG)
        xray_process = subprocess.Popen(["/usr/local/bin/xray", "-config", CFG_FILE],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                         env=get_xray_env())
    except: pass

# لاک برای جلوگیری از فراخوانی همزمان sync_xray_config از چند جا (مثلاً وقتی یک کاربر هم‌زمان
# با تیک ۱۵ ثانیه‌ای stats_updater، یک API ریکوئست هم لینک جدید می‌سازد). بدون این لاک، دو
# thread/کوروتین می‌توانند هم‌زمان xray_process را terminate/spawn کنند و یک پروسهٔ Xray یتیم
# (orphan) یا حالت ناپایدار بسازند که به‌مرور رم زیادی مصرف می‌کند.
_xray_restart_lock = asyncio.Lock()

async def sync_xray_config_async():
    """
    نسخهٔ async برای فراخوانی از مسیر هندل کردن ریکوئست‌های HTTP و از stats_updater.
    sync_xray_config() پروسهٔ Xray را kill/spawn می‌کند و فایل کانفیگ را روی دیسک می‌نویسد —
    هر دو عملیات بلاکینگ هستند. قبلاً این تابع مستقیماً (سینک) از داخل endpointهای async مثل
    create_link/edit_link/delete_link و از حلقهٔ stats_updater صدا زده می‌شد؛ یعنی هر بار که
    کاربری لینک می‌ساخت/حذف می‌کرد یا یک کاربر expire می‌شد، کل event loop برای مدتی (kill
    پروسهٔ قبلی Xray + ساخت پروسهٔ جدید با ۸ inbound و صدها client) قفل می‌شد و همان لحظه هیچ
    درخواست دیگری (ساب‌اسکریپشن/پنل) پاسخ نمی‌گرفت. اینجا با run_in_executor در thread جدا
    اجرا می‌شود، و با _xray_restart_lock تضمین می‌شود دو ری‌استارت هم‌زمان رخ ندهد.
    """
    async with _xray_restart_lock:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, sync_xray_config)

def _read_log_segment_sync(path, pos, max_size):
    """
    خواندن سینک یک بخش از فایل لاگ (truncate در صورت بزرگ شدن بیش از max_size، سیک به pos،
    خواندن داده‌های جدید). این تابع عمداً sync نوشته شده تا بتوان آن را با run_in_executor
    در یک thread جدا اجرا کرد — چون با ۱۰۰ کاربر روی ۸ پروتکل، فایل لاگ Xray/Nginx می‌تواند
    هر ۱۵ ثانیه چند صد کیلوبایت تا چند مگابایت داده جدید داشته باشد و خواندن سینک آن مستقیماً
    روی event loop اصلی، باعث می‌شد در همان لحظه پاسخ به ریکوئست‌های HTTP کاربران معطل بماند.
    خروجی: (new_data: str, new_pos: int)
    """
    if not os.path.exists(path):
        return "", pos
    if os.path.getsize(path) > max_size:
        open(path, 'w').close()
        pos = 0
    current_size = os.path.getsize(path)
    if current_size < pos:
        pos = 0
    with open(path, "r") as f:
        f.seek(pos)
        new_data = f.read()
        new_pos = f.tell()
    return new_data, new_pos

async def _read_log_segment_async(path, pos, max_size):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _read_log_segment_sync, path, pos, max_size)

# شمارندهٔ ذخیرهٔ دوره‌ای آمار (لیست تک‌عضوی تا داخل کوروتین بدون global قابل تغییر باشد)
stats_save_counter = [0]
LOG_CAP_BYTES = 5 * 1024 * 1024  # سقف اندازهٔ هر فایل لاگ قبل از چرخش

def _rotate_logs_sync():
    """اگر فایل‌های لاگ از سقف رد شدند، کوتاه‌شان کن و به writer بگو فایل را دوباره باز کند.
    Xray با restartlogger و Nginx با `nginx -s reopen` فایل را تازه باز می‌کنند تا فایل sparse نشود."""
    global xray_log_pos, nginx_log_pos
    try:
        if os.path.exists(XRAY_LOG) and os.path.getsize(XRAY_LOG) > LOG_CAP_BYTES:
            open(XRAY_LOG, "w").close()
            _xray_api(["restartlogger"], timeout=3)
            xray_log_pos = 0
    except Exception:
        pass
    try:
        if os.path.exists(NGINX_LOG) and os.path.getsize(NGINX_LOG) > LOG_CAP_BYTES:
            open(NGINX_LOG, "w").close()
            subprocess.run(["nginx", "-s", "reopen"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            nginx_log_pos = 0
    except Exception:
        pass

async def rotate_logs_if_big():
    await asyncio.get_running_loop().run_in_executor(None, _rotate_logs_sync)

NGINX_PORT = os.environ.get("PORT", "8000")  # پورتی که نگینکس روی آن گوش می‌دهد (در run.sh جایگزین می‌شود)
_NGINX_STATUS_RE = re.compile(
    r"Active connections:\s*(\d+).*?Reading:\s*(\d+)\s+Writing:\s*(\d+)\s+Waiting:\s*(\d+)",
    re.IGNORECASE | re.DOTALL,
)

async def update_net_info():
    """شمارش دقیق اتصالات هم‌زمان را از stub_status نگینکس می‌خواند (localhost، بسیار سبک).
    Active = کل اتصالات باز نگینکس (شامل WS کاربران + چند اتصال داخلی پنل). Writing معمولاً
    به اتصالات در حال انتقال داده اشاره دارد. اگر نگینکس در دسترس نبود، بی‌صدا رد می‌شود."""
    try:
        async with httpx.AsyncClient(timeout=2) as client:
            resp = await client.get(f"http://127.0.0.1:{NGINX_PORT}/nginx_status")
        m = _NGINX_STATUS_RE.search(resp.text or "")
        if m:
            net_info["active"]  = int(m.group(1))
            net_info["reading"] = int(m.group(2))
            net_info["writing"] = int(m.group(3))
            net_info["waiting"] = int(m.group(4))
    except Exception:
        pass

async def stats_updater():
    global xray_log_pos, nginx_log_pos
    await asyncio.sleep(5)
    while True:
        get_sys_info()
        if xray_process and xray_process.poll() is not None: await sync_xray_config_async()

        # ۱. خواندن ترافیک از Xray API (هر ۱۵ ثانیه)
        # نکته مهم: قبلاً اینجا subprocess.run (بلاکینگ) صدا زده می‌شد که با ۱۰۰+ کاربر
        # و ۸ پروتکل همزمان، کل event loop اصلی (همان loopی که همه ریکوئست‌های HTTP/ساب‌اسکریپشن/پنل
        # رو هم سرویس می‌دهد) را برای صدها میلی‌ثانیه تا چند ثانیه کامل می‌بست — یعنی در همان لحظه
        # هیچ کاربری نمی‌توانست ساب‌اسکریپشن بگیرد یا به پنل وصل شود. با asyncio.create_subprocess_exec
        # این subprocess به‌صورت ناهمزمان اجرا می‌شود و event loop آزاد می‌ماند.
        try:
            proc = await asyncio.create_subprocess_exec(
                "/usr/local/bin/xray", "api", "statsquery", f"--server=127.0.0.1:{XRAY_API_PORT}", "-reset",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
            )
            try:
                stdout_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=3)
            except asyncio.TimeoutError:
                try: proc.kill()
                except Exception: pass
                stdout_bytes = b""
            stdout_text = stdout_bytes.decode("utf-8", "ignore") if stdout_bytes else ""
            if stdout_text:
                data = json.loads(stdout_text)
                for stat in data.get("stat", []):
                    name  = stat.get("name", "")
                    value = int(stat.get("value", "0") or "0")
                    parts = name.split(">>>")
                    if len(parts) == 4 and parts[0] == "user" and parts[2] == "traffic":
                        uid = parts[1]
                        direction = parts[3]  # "uplink" یا "downlink" — برای محاسبهٔ سرعت واقعی مجزا
                        if uid not in user_traffic: user_traffic[uid] = 0
                        user_traffic[uid] += value
                        stats["bytes"] += value
                        if direction == "downlink": stats["down_bytes"] += value
                        elif direction == "uplink": stats["up_bytes"] += value
                        if value > 0:
                            user_last_active[uid] = time.time()
                            if uid in user_protocol_active:
                                for p in list(user_protocol_active[uid].keys()):
                                    t = PROTO_TO_TAG.get(p)
                                    if t and time.time() - inbound_last_active.get(t, 0) < 30:
                                        user_protocol_active[uid][p] = time.time()
                    elif len(parts) == 4 and parts[0] == "inbound" and parts[2] == "traffic":
                        # این شمارنده مستقیماً از خود Xray می‌آید، پس بدون توجه به اینکه Nginx ایپی واقعی
                        # کاربر را نشان می‌دهد یا نه، دقیقاً می‌فهمیم همین الان از کدام پروتکل ترافیک رد شده.
                        tag = parts[1]
                        if value > 0: inbound_last_active[tag] = time.time()
            # ذخیره‌سازی دیگر اینجا (هر چرخه) انجام نمی‌شود؛ به‌صورت دوره‌ای در انتهای حلقه ذخیره می‌شود.
        except: pass

        # ۲. خواندن لاگ Nginx برای شمارش *دقیق* ایپی‌های واقعی فعال روی /ws
        # نکته مهم: روی هاست‌هایی مثل Railway، نگینکس از طریق یک پراکسی داخلی پلتفرم به کانتینر می‌رسد،
        # پس $remote_addr همان ایپی داخلی پلتفرم است نه ایپی واقعی کاربر؛ ایپی واقعی در هدر X-Forwarded-For می‌آید.
        # اگر $remote_addr خودش عمومی بود (یعنی نگینکس مستقیم در معرض اینترنت است) همان قابل اعتمادتر است.
        try:
            new_data, nginx_log_pos = await _read_log_segment_async(NGINX_LOG, nginx_log_pos, 1 * 1024 * 1024)
            if new_data:
                now_t1 = time.time()
                for line in new_data.splitlines():
                    fields = line.strip().split("|")
                    if len(fields) < 3: continue
                    remote_addr, xff = fields[0], fields[1]
                    # نکته: بایت‌های Nginx به stats["bytes"] اضافه نمی‌شوند. منبع واحد و دقیق حجم،
                    # شمارندهٔ خود Xray است. لاگ Nginx فقط برای تشخیص ایپی واقعی فعال استفاده می‌شود.
                    real_ip = remote_addr if is_public_ip(remote_addr) else ""
                    if not real_ip and xff:
                        first_ip = xff.split(",")[0].strip()
                        if is_public_ip(first_ip): real_ip = first_ip
                    if not real_ip: continue
                    if len(total_unique_ips) < 2000: total_unique_ips.add(real_ip)
                    if len(ws_connections) < 5000 or real_ip in ws_connections:
                        ws_connections[real_ip] = now_t1
                    proto = fields[3].strip() if len(fields) >= 4 else None
                    if proto:
                        if proto not in protocol_connections: protocol_connections[proto] = {}
                        protocol_connections[proto][real_ip] = now_t1
        except: pass

        # ۳. خواندن لاگ Xray برای تشخیص اینکه کدام کاربر (UUID) آنلاین است.
        # لاگ Xray شامل تگ inbound و ایمیل (UUID) هر اتصال است. برای WS ایپی همیشه 127.0.0.1 است
        # (چون از Nginx رد شده)، پس فقط آنلاین‌بودنِ کاربر را از آن می‌گیریم؛ ایپیِ واقعی از لاگ Nginx می‌آید.
        try:
            new_data, xray_log_pos = await _read_log_segment_async(XRAY_LOG, xray_log_pos, 2 * 1024 * 1024)
            if new_data:
                now_t = time.time()
                for m in XRAY_RE.finditer(new_data):
                    ip, tag, uid = m.group(1), m.group(2), m.group(3)
                    if uid not in LINKS: continue
                    proto = TAG_TO_PROTO.get(tag)
                    if not proto: continue
                    if uid not in user_protocol_active:
                        user_protocol_active[uid] = {}
                    user_protocol_active[uid][proto] = now_t
                    user_last_active[uid] = now_t
        except: pass

        # ۴. خواندن شمارش دقیق اتصالات هم‌زمان از stub_status نگینکس (همان عددی که خود نگینکس می‌بیند).
        await update_net_info()

        # ۵. پاکسازی حافظه
        now = time.time()
        for uid in list(user_last_active.keys()):
            if now - user_last_active[uid] > 60: del user_last_active[uid]
        for ip in list(ws_connections.keys()):
            if now - ws_connections[ip] > 60: del ws_connections[ip]
        for proto in list(protocol_connections.keys()):
            for ip in list(protocol_connections[proto].keys()):
                if now - protocol_connections[proto][ip] > 60: del protocol_connections[proto][ip]
            if not protocol_connections[proto]: del protocol_connections[proto]
        for uid in list(user_protocol_active.keys()):
            for proto in list(user_protocol_active[uid].keys()):
                if now - user_protocol_active[uid][proto] > 60: del user_protocol_active[uid][proto]
            if not user_protocol_active[uid]: del user_protocol_active[uid]
        # پاکسازی inbound_last_active (۶۰ ثانیه بعد از آخرین ترافیک)
        for tag in list(inbound_last_active.keys()):
            if now - inbound_last_active[tag] > 60: del inbound_last_active[tag]

        for t in list(SESSIONS.keys()):
            if now > SESSIONS.get(t, 0): del SESSIONS[t]

        # ۶. محاسبهٔ سرعت واقعی دانلود/آپلود (مجزا، از شمارندهٔ خود Xray — نه تخمین ساختگی ۶۵/۳۵)
        now_t2 = time.time()
        elapsed = now_t2 - stats["bytes_prev_time"]
        if elapsed > 0:
            stats["dl_speed"] = int(max(0, stats["down_bytes"] - stats["down_prev"]) / elapsed)
            stats["ul_speed"] = int(max(0, stats["up_bytes"] - stats["up_prev"]) / elapsed)
            stats["down_prev"] = stats["down_bytes"]
            stats["up_prev"] = stats["up_bytes"]
            stats["bytes_prev"] = stats["bytes"]
            stats["bytes_prev_time"] = now_t2

        # ۷. بررسی انقضا و سقف حجم — بدون ری‌استارت کامل!
        # قبلاً هر تخطی کل Xray را ری‌استارت می‌کرد و *همهٔ* کاربران قطع می‌شدند. حالا فقط همان کاربر
        # متخلف با rmu به‌صورت هات حذف می‌شود و بقیه دست‌نخورده می‌مانند.
        # نکته: سقف تعداد دستگاه (ip_limit) برای WS-پشت-نگینکس قابل اعمال دقیق نیست (Xray ایپی واقعیِ
        # هر کاربر را پشت نگینکس نمی‌بیند؛ همه 127.0.0.1 دیده می‌شوند)، پس اینجا فقط انقضا و حجم اعمال می‌شود.
        to_disable = []
        for uid, info in list(LINKS.items()):
            if info.get("status") != "active": continue
            if info.get("expiry_time") and time.time() > info["expiry_time"]:
                info["status"] = "expired"; to_disable.append(uid); continue
            if info.get("data_limit") and user_traffic.get(uid, 0) >= info["data_limit"]:
                info["status"] = "expired"; to_disable.append(uid); continue
        if to_disable:
            save_links()
            for uid in to_disable:
                await remove_user_hot_async(uid)

        # ۸. چرخش امن لاگ‌ها (با حذف ری‌استارت‌ها دیگر خودبه‌خود پاک نمی‌شوند → باید از پر شدن /tmp جلوگیری کنیم)
        await rotate_logs_if_big()

        # ۹. ذخیرهٔ دوره‌ای آمار (هر ~۳۰ ثانیه به‌جای هر چرخه، برای کاهش I/O دیسک)
        stats_save_counter[0] += 1
        if stats_save_counter[0] >= 6:
            stats_save_counter[0] = 0
            await save_stats_async()

        # خواب ۵ ثانیه (به‌جای ۱۵): سرعت ۳ برابر سریع‌تر آپدیت می‌شود و آنلاین‌بودن کاربران زودتر تشخیص داده می‌شود.
        await asyncio.sleep(5)

# ── متریک‌های واقعی ریلوی (رم/ترافیک/دیسک) ──────────────────
# نکته مهم: ریلوی یک API عمومی رسمی برای این متریک‌ها منتشر نکرده؛ اینجا همان کوئری گرافیک‌کیوال
# داخلی‌ای استفاده شده که خودِ داشبورد ریلوی هم استفاده می‌کند. اگر روزی ریلوی این را تغییر دهد،
# این بخش فقط بی‌صدا غیرفعال می‌شود (available=False) و بقیه پنل کاملاً سالم کار می‌کند.
async def fetch_railway_metrics():
    if not RAILWAY_API_TOKEN or not RAILWAY_SERVICE_ID or not RAILWAY_ENVIRONMENT_ID:
        return
    try:
        now = datetime.utcnow()
        start = now - timedelta(minutes=10)
        query = """
        query Metrics($measurements: [MetricMeasurement!]!, $startDate: DateTime!, $endDate: DateTime, $environmentId: String, $serviceId: String) {
          metrics(measurements: $measurements, startDate: $startDate, endDate: $endDate, environmentId: $environmentId, serviceId: $serviceId) {
            measurement
            values { ts value }
          }
        }
        """
        variables = {
            # نکته: enum واقعی ریلوی "DISK_LIMIT_GB" ندارد (طبق introspection زنده) — همان چیزی که باعث
            # خطای 400 می‌شد. دیسک هم اصلاً اینجا درخواست نمی‌شود چون EPHEMERAL_DISK_USAGE_GB برای این
            # سرویس داده‌ای برنمی‌گرداند و DISK_USAGE_GB (مخصوص Volume) همیشه صفر است؛ دیسک واقعی را
            # مستقیماً و محلی از خود کانتینر می‌خوانیم (تابع get_sys_info)، نه از این API.
            "measurements": ["MEMORY_USAGE_GB", "MEMORY_LIMIT_GB", "NETWORK_RX_GB", "NETWORK_TX_GB"],
            "startDate": start.isoformat() + "Z",
            "endDate": now.isoformat() + "Z",
            "environmentId": RAILWAY_ENVIRONMENT_ID,
            "serviceId": RAILWAY_SERVICE_ID,
        }
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                RAILWAY_GRAPHQL_URL,
                json={"query": query, "variables": variables},
                headers={"Authorization": f"Bearer {RAILWAY_API_TOKEN}", "Content-Type": "application/json"},
            )
        data = resp.json()
        if "errors" in data:
            log_err(f"railway_metrics_api: {data['errors']}")
            railway_metrics["available"] = False
            return

        results = {item["measurement"]: (item.get("values") or []) for item in (data.get("data", {}) or {}).get("metrics", []) or []}

        # رم: یک gauge لحظه‌ای است؛ فقط آخرین مقدار کافی است.
        mem_vals = results.get("MEMORY_USAGE_GB", [])
        lim_vals = results.get("MEMORY_LIMIT_GB", [])
        mem_used = mem_vals[-1]["value"] if mem_vals else 0
        mem_limit = lim_vals[-1]["value"] if lim_vals else 0

        # ترافیک: ریلوی برای هر بازه (~۶۰ ثانیه) مقدار مصرفی همان بازه را برمی‌گرداند، نه یک عدد تجمعی!
        # (مقادیر بالا و پایین می‌روند، نشانه‌ی delta بودن نه cumulative). پس برای «ترافیک کل» باید
        # هر بار فقط بازه‌های جدید (ts بزرگ‌تر از آخرین ts دیده‌شده) را به یک شمارنده‌ی دائمی اضافه کنیم.
        def accumulate(values, total_key, ts_key):
            last_ts = railway_metrics.get(ts_key, 0)
            new_total = railway_metrics.get(total_key, 0)
            max_ts = last_ts
            for v in sorted(values, key=lambda x: x.get("ts", 0)):
                ts = v.get("ts", 0)
                if ts > last_ts:
                    new_total += (v.get("value") or 0)
                    if ts > max_ts: max_ts = ts
            railway_metrics[total_key] = new_total
            railway_metrics[ts_key] = max_ts
            return new_total

        net_rx_total = accumulate(results.get("NETWORK_RX_GB", []), "net_rx_total_gb", "net_rx_last_ts")
        net_tx_total = accumulate(results.get("NETWORK_TX_GB", []), "net_tx_total_gb", "net_tx_last_ts")
        await save_stats_async()  # ذخیره شمارنده‌های تجمعی ترافیک ریلوی تا بین ری‌استارت‌ها از دست نروند

        railway_metrics.update({
            "available": True,
            "ram_pct": round(mem_used / mem_limit * 100, 1) if mem_limit else 0,
            "mem_used_gb": round(mem_used, 2), "mem_limit_gb": round(mem_limit, 2),
            "net_rx_gb": round(net_rx_total, 3), "net_tx_gb": round(net_tx_total, 3),
            "net_bytes": int((net_rx_total + net_tx_total) * (1024 ** 3)),
            "updated": time.time(),
        })
    except Exception as e:
        log_err(f"railway_metrics_error: {e}")
        railway_metrics["available"] = False

async def railway_metrics_updater():
    if not RAILWAY_API_TOKEN or not RAILWAY_SERVICE_ID or not RAILWAY_ENVIRONMENT_ID:
        return  # اگر توکن یا environment_id ست نشده، اصلاً این تسک سبک حلقه نمی‌زند
    while True:
        await fetch_railway_metrics()
        await asyncio.sleep(60)  # هر ۶۰ ثانیه؛ سبک و بدون فشار به CPU/رم

async def telegram_notifier():
    if not BOT_TOKEN or not ADMIN_CHAT_ID: return
    await asyncio.sleep(10)
    while True:
        for uid, info in LINKS.items():
            if info.get("status") != "active": continue
            notified = info.get("notified", False)
            msg = ""
            if info.get("expiry_time"):
                days_left = (info["expiry_time"] - time.time()) / 86400
                if days_left <= 3 and days_left > 0: msg = f"⚠️ کاربر {info['label']} کمتر از ۳ روز تا انقضا دارد."
            if info.get("data_limit"):
                used = user_traffic.get(uid, 0)
                if used >= info["data_limit"] * 0.9: msg = f"⚠️ کاربر {info['label']} ۹۰٪ حجم خود را مصرف کرده است."
            
            if msg and not notified:
                try:
                    await tg_request("sendMessage", {"chat_id": ADMIN_CHAT_ID, "text": msg})
                    LINKS[uid]["notified"] = True
                    save_links()
                except: pass
            elif not msg and notified:
                LINKS[uid]["notified"] = False
                save_links()
        await asyncio.sleep(3600) 

@asynccontextmanager
async def lifespan(app: FastAPI):
    global tg_client
    load_data()
    if MASTER_UUID not in LINKS:
        LINKS[MASTER_UUID] = {"label": "Master", "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"), "status": "active", "short_id": secrets.token_hex(4)[:7], "clean_ip": ""}
        save_links()
    sync_xray_config()
    asyncio.create_task(stats_updater())
    asyncio.create_task(telegram_notifier())
    asyncio.create_task(railway_metrics_updater())
    
    if BOT_TOKEN:
        tg_client = httpx.AsyncClient()
        domain = PUBLIC_HOST or os.environ.get("RAILWAY_PUBLIC_DOMAIN", "")
        if domain: asyncio.create_task(set_telegram_webhook(domain))
        
    yield
    if tg_client: await tg_client.aclose()
    if xray_process: xray_process.terminate()

app = FastAPI(docs_url=None, redoc_url=None, lifespan=lifespan)

# ── helpers ───────────────────────────────────────────────
def get_domain(request: Request) -> str:
    h = (PUBLIC_HOST or os.environ.get("RENDER_EXTERNAL_URL","") or os.environ.get("RAILWAY_PUBLIC_DOMAIN","") or request.headers.get("host","localhost"))
    return h.replace("https://","").replace("http://","").strip("/")

def make_links(uid: str, domain: str, label: str, short_id: str, clean_ip: str = "") -> dict:
    """تنها لینک VLESS + WS + TLS را می‌سازد (بقیهٔ پروتکل‌ها حذف شده‌اند)."""
    addr = clean_ip if clean_ip else domain
    ws = f"vless://{uid}@{addr}:443?encryption=none&security=tls&type=ws&host={domain}&path=%2Fws&sni={domain}&fp=chrome#{label}-WS"
    sub_link = f"https://{domain}/sub/{short_id}"
    sub_base64 = base64.b64encode(ws.encode()).decode()
    return {"ws": ws, "sub_link": sub_link, "sub_base64": sub_base64}

def make_clash_config(uid: str, domain: str, label: str, clean_ip: str = "") -> str:
    addr = clean_ip if clean_ip else domain
    proxy = f'  - {{name: "{label}-WS", type: vless, server: {addr}, port: 443, uuid: {uid}, tls: true, servername: {domain}, network: ws, ws-opts: {{path: "/ws", headers: {{Host: {domain}}}}}}}'
    return f"proxies:\n{proxy}\nproxy-groups:\n  - name: PROXY\n    type: select\n    proxies:\n      - {label}-WS\nrules:\n  - GEOIP,IR,DIRECT\n  - MATCH,PROXY\n"

def auth_check(token: Optional[str] = Cookie(None)) -> bool:
    if not token: return False
    return time.time() < SESSIONS.get(token, 0)

def uptime_str() -> str:
    s = int(time.time() - stats["start"]); h, r = divmod(s, 3600); m, sc = divmod(r, 60)
    return f"{h:02d}:{m:02d}:{sc:02d}"

def fmt_bytes(b):
    if b < 1024: return f"{b} B"
    if b < 1024**2: return f"{b/1024:.1f} KB"
    if b < 1024**3: return f"{b/1024**2:.2f} MB"
    return f"{b/1024**3:.2f} GB"

def fmt_speed(bps):
    return fmt_bytes(int(bps)) + "/s"

def build_active_configs():
    """
    لیست کاربران آنلاین را می‌سازد.
    مرحله ۱: از user_protocol_active (mapping دقیق از لاگ Xray) استفاده می‌کند.
    مرحله ۲: fallback — کاربرانی که آنلاین هستند ولی هنوز mapping ندارند.
    """
    items = []
    now = time.time()
    mapped_uids = set()

    # مرحله ۱: کاربران با mapping دقیق (از لاگ Xray)
    proto_users = {}
    for uid, protos in user_protocol_active.items():
        if uid not in LINKS: continue
        label = LINKS[uid].get("label", uid[:8])
        for proto, last_seen in protos.items():
            if now - last_seen > 60: continue
            if proto not in proto_users:
                proto_users[proto] = []
            proto_users[proto].append({"uid": uid, "label": label})
            mapped_uids.add(uid)

    for proto, users in proto_users.items():
        if not users: continue
        config_label = PROTOCOL_LABELS.get(proto, proto)
        ip_count = len(protocol_connections.get(proto, {})) or len(users)
        for user in users:
            items.append({"config": config_label, "label": user["label"], "ip_count": 1, "attributed": True})

    # مرحله ۲: fallback — کاربرانی که آنلاین هستند (Stats API) ولی mapping ندارند
    unmapped_online = [uid for uid in user_last_active if uid in LINKS and uid not in mapped_uids
                       and now - user_last_active[uid] <= 60]
    for uid in unmapped_online:
        label = LINKS[uid].get("label", uid[:8])
        items.append({"config": PROTOCOL_LABELS.get("ws", "VLESS + WS + TLS"), "label": label, "ip_count": 1, "attributed": True})
    return items

def format_active_configs_text(items):
    if not items: return "هیچ کانفیگ آنلاینی وجود ندارد."
    lines = []
    for it in items:
        lines.append(f"🔌 {it['config']} — کاربر {it['label']} آنلاین")
    return "\n".join(lines)

# ── auth & api ───────────────────────────────────────────
@app.post("/api/login")
async def login(request: Request):
    ip = request.client.host
    if not rate_limiter(ip, "login"): raise HTTPException(429, "درخواست بیش از حد. بعداً تلاش کنید.")
    d = await request.json()
    if hashlib.sha256(d.get("password","").encode()).hexdigest() != PASS_HASH: raise HTTPException(403, "رمز اشتباه است")
    token = secrets.token_urlsafe(32); SESSIONS[token] = time.time() + 86400
    r = JSONResponse({"ok": True}); r.set_cookie("token", token, httponly=True, samesite="lax", max_age=86400); return r

@app.post("/api/logout")
async def logout(token: Optional[str] = Cookie(None)):
    SESSIONS.pop(token, None); r = JSONResponse({"ok": True}); r.delete_cookie("token"); return r

@app.get("/api/stats")
async def api_stats(request: Request, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    active_configs = build_active_configs()
    return {
        "total_users": len(LINKS),
        # شمارش‌های دقیق:
        "live_connections": net_info.get("active", 0),   # اتصالات هم‌زمان نگینکس (stub_status) — دقیق
        "active_ips": len(ws_connections),                # ایپی‌های واقعیِ فعال روی /ws (پنجرهٔ ۶۰ث) — دقیق
        "active_uuids": len(user_last_active),            # کاربران آنلاین (UUID) — دقیق
        "total_connected": len(total_unique_ips),         # کل ایپی‌های دیده‌شده از ابتدا (تجمعی)
        "bytes": stats["bytes"],
        "dl_speed": stats.get("dl_speed", 0),
        "ul_speed": stats.get("ul_speed", 0),
        "uptime": uptime_str(),
        "ram": sys_info["ram"],
        "ram_used_mb": sys_info.get("ram_used_mb", 0),
        "ram_limit_mb": sys_info.get("ram_limit_mb", 0),
        "cpu": sys_info["cpu"],
        "cpu_cores": sys_info.get("cpu_cores", 0),
        "active_configs": active_configs,
        "railway_available": railway_metrics["available"],
        "railway_ram_pct": railway_metrics["ram_pct"],
        "railway_net_bytes": railway_metrics["net_bytes"],
        "disk_used_gb": sys_info["disk_used_gb"],
        "disk_total_gb": sys_info["disk_total_gb"],
        "disk_pct": sys_info["disk_pct"],
        "combined_bytes": stats["bytes"] + railway_metrics["net_bytes"],
    }

def _tail_file_sync(path, n_lines, max_read_bytes=256 * 1024):
    """
    فقط بخش انتهایی فایل را می‌خواند (نه کل فایل) تا n_lines خط آخر را برگرداند.
    قبلاً اینجا f.readlines() کل فایل لاگ Xray را به حافظه می‌آورد و فقط ۵۰ خط آخرش
    استفاده می‌شد؛ با ۱۰۰ کاربر روی ۸ پروتکل، این فایل می‌تواند چند مگابایت باشد و این کار
    باعث یک اسپایک ناگهانی رم (و کند شدن) فقط برای نمایش ۵۰ خط در پنل ادمین می‌شد.
    """
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            seek_to = max(0, size - max_read_bytes)
            f.seek(seek_to)
            data = f.read()
        text = data.decode("utf-8", "ignore")
        lines = text.splitlines()
        return [l + "\n" for l in lines[-n_lines:]]
    except Exception:
        return []

@app.get("/api/logs")
async def api_logs(token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    logs = []
    if os.path.exists(XRAY_LOG):
        loop = asyncio.get_running_loop()
        logs.extend(await loop.run_in_executor(None, _tail_file_sync, XRAY_LOG, 50))
    if error_log:
        logs.append("──── آخرین خطاهای پنل (شامل دیباگ ریلوی) ────")
        for e in list(error_log)[-15:]:
            logs.append(f"[{e['t']}] {e['e']}")
    return {"logs": logs}

def _gql_type_str(t):
    """تبدیل ساختار تایپ introspection گرافیک‌کیوال به یک رشته خوانا مثل [MetricMeasurement!]!"""
    if not t: return None
    kind = t.get("kind")
    if kind == "NON_NULL": return (_gql_type_str(t.get("ofType")) or "?") + "!"
    if kind == "LIST": return "[" + (_gql_type_str(t.get("ofType")) or "?") + "]"
    return t.get("name")

async def railway_introspect():
    """
    وقتی کوئری metrics خطا می‌دهد، کل اسکیمای ریلوی (همه تایپ‌ها) را می‌خوانیم و فقط تایپ‌های
    مرتبط با Metric را فیلتر می‌کنیم. این‌طوری هم آرگومان‌های فیلد metrics و هم خودِ فیلدهای
    دقیق نوع برگشتی‌اش (مثلاً MetricResult/MetricValue/MetricTags) را می‌بینیم — نه فقط حدس.
    """
    introspect_query = """
    query Introspect {
      __schema {
        queryType {
          fields {
            name
            args { name type { ...T } }
          }
        }
        types {
          name
          kind
          fields { name type { ...T } }
          enumValues { name }
        }
      }
    }
    fragment T on __Type {
      kind name
      ofType { kind name ofType { kind name ofType { kind name } } }
    }
    """
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            RAILWAY_GRAPHQL_URL, json={"query": introspect_query},
            headers={"Authorization": f"Bearer {RAILWAY_API_TOKEN}", "Content-Type": "application/json"},
        )
    body = resp.json()
    if "errors" in body:
        return {"introspection_error": body["errors"]}
    schema = (body.get("data") or {}).get("__schema") or {}
    root_fields = (schema.get("queryType") or {}).get("fields") or []
    metric_fields = []
    for f in root_fields:
        if "metric" in (f.get("name") or "").lower():
            args = [{"name": a["name"], "type": _gql_type_str(a.get("type"))} for a in (f.get("args") or [])]
            metric_fields.append({"name": f["name"], "args": args})

    metric_types = []
    for t in (schema.get("types") or []):
        if "metric" in (t.get("name") or "").lower():
            entry = {"name": t.get("name"), "kind": t.get("kind")}
            if t.get("fields"):
                entry["fields"] = [{"name": fl["name"], "type": _gql_type_str(fl.get("type"))} for fl in t["fields"]]
            if t.get("enumValues"):
                entry["enumValues"] = [v["name"] for v in t["enumValues"]]
            metric_types.append(entry)

    return {"metric_query_fields": metric_fields, "metric_types": metric_types}

@app.get("/api/railway-test")
async def railway_test(token: Optional[str] = Cookie(None)):
    """یک تست زنده و فوری (بدون کش) برای دیباگ اتصال به API ریلوی؛ خطای دقیق را برمی‌گرداند."""
    if not auth_check(token): raise HTTPException(401)
    out = {
        "token_set": bool(RAILWAY_API_TOKEN),
        "service_id": RAILWAY_SERVICE_ID or None,
        "environment_id": RAILWAY_ENVIRONMENT_ID or None,
        "project_id": RAILWAY_PROJECT_ID or None,
    }
    if not RAILWAY_API_TOKEN:
        out["result"] = "RAILWAY_API_TOKEN ست نشده. آن را در Variables پروژه اضافه کنید و سرویس را Redeploy کنید."
        return out
    if not RAILWAY_SERVICE_ID:
        out["result"] = "RAILWAY_SERVICE_ID خوانده نشد (باید خودکار توسط ریلوی ست شود؛ یعنی این پنل احتمالاً خارج از ریلوی اجرا می‌شود یا نیاز به Redeploy دارد)."
        return out
    if not RAILWAY_ENVIRONMENT_ID:
        out["result"] = "RAILWAY_ENVIRONMENT_ID خوانده نشد (باید خودکار توسط ریلوی ست شود؛ نیاز به Redeploy دارد)."
        return out
    try:
        now = datetime.utcnow()
        start = now - timedelta(minutes=10)
        query = """
        query Metrics($measurements: [MetricMeasurement!]!, $startDate: DateTime!, $endDate: DateTime, $environmentId: String, $serviceId: String) {
          metrics(measurements: $measurements, startDate: $startDate, endDate: $endDate, environmentId: $environmentId, serviceId: $serviceId) {
            measurement
            values { ts value }
          }
        }
        """
        variables = {
            "measurements": ["MEMORY_USAGE_GB", "MEMORY_LIMIT_GB", "NETWORK_RX_GB", "NETWORK_TX_GB", "EPHEMERAL_DISK_USAGE_GB", "DISK_USAGE_GB"],
            "startDate": start.isoformat() + "Z",
            "endDate": now.isoformat() + "Z",
            "environmentId": RAILWAY_ENVIRONMENT_ID,
            "serviceId": RAILWAY_SERVICE_ID,
        }
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                RAILWAY_GRAPHQL_URL,
                json={"query": query, "variables": variables},
                headers={"Authorization": f"Bearer {RAILWAY_API_TOKEN}", "Content-Type": "application/json"},
            )
        out["http_status"] = resp.status_code
        try:
            body = resp.json()
        except Exception:
            out["result"] = "پاسخ ریلوی JSON نبود."
            out["raw_body"] = resp.text[:800]
            return out
        if "errors" in body:
            out["result"] = "ریلوی خطا برگرداند؛ برای پیداکردن اسم درست فیلدها از خود اسکیمای ریلوی introspection گرفتم (پایین را ببین) — این خروجی کامل را برام بفرست."
            out["graphql_errors"] = body["errors"]
            try:
                out["schema_introspection"] = await railway_introspect()
            except Exception as e:
                out["schema_introspection_error"] = str(e)
            return out
        metrics = (body.get("data") or {}).get("metrics") or []
        out["result"] = "موفق ✓" if metrics else "اتصال موفق بود اما هیچ متریکی برنگشت (ممکن است بازه زمانی داده نداشته باشد یا اشتراک ریلوی این داده را ندهد)."
        out["measurements_returned"] = [m.get("measurement") for m in metrics]
        out["sample"] = metrics
        return out
    except httpx.RequestError as e:
        out["result"] = f"خطای شبکه در اتصال به ریلوی: {e}"
        return out
    except Exception as e:
        out["result"] = f"خطای ناشناخته: {e}"
        return out

@app.get("/api/links")
async def api_links(request: Request, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    domain = get_domain(request); out = []
    now = time.time()
    for uid, info in LINKS.items():
        is_online = uid in user_last_active and now - user_last_active[uid] <= 60
        data_limit = info.get("data_limit", 0)
        used_traffic = user_traffic.get(uid, 0)
        remaining_data = (data_limit - used_traffic) if data_limit else 0
        expiry_time = info.get("expiry_time", 0)
        remaining_days = max(0, int((expiry_time - time.time()) / 86400)) if expiry_time else 0
        out.append({
            "uuid": uid, "label": info["label"], "created_at": info["created_at"],
            "online": is_online, "used_traffic": used_traffic,
            "status": info.get("status", "active"),
            "data_limit": data_limit, "remaining_data": remaining_data,
            "remaining_days": remaining_days, "short_id": info.get("short_id", ""),
            **make_links(uid, domain, info["label"], info.get("short_id", ""), info.get("clean_ip", ""))
        })
    return {"links": out}

@app.post("/api/links")
async def create_link(request: Request, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    ip = request.client.host
    if not rate_limiter(ip, "create"): raise HTTPException(429, "درخواست بیش از حد.")
    d = await request.json()
    uid = d.get("uuid") or str(uuid.uuid4())
    label = sanitize_label(d.get("label", "کاربر"))
    clean_ip = d.get("clean_ip", "")
    short_id = d.get("short_id") or secrets.token_hex(4)[:7]
    days = int(d.get("days", 0) or 0)
    gb = float(d.get("gb", 0) or 0)

    info = {"label": label, "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"), "status": "active", "short_id": short_id, "clean_ip": clean_ip}
    if days > 0: info["expiry_time"] = time.time() + (days * 86400)
    if gb > 0: info["data_limit"] = int(gb * 1024 * 1024 * 1024)

    LINKS[uid] = info
    save_links()
    # افزودن هات بدون ری‌استارت؛ fallback ایمن اگر افزودن هات شکست خورد.
    if not await add_user_hot_async(uid):
        await sync_xray_config_async()
    domain = get_domain(request)
    return {"ok": True, "uuid": uid, **make_links(uid, domain, label, short_id, clean_ip)}

@app.post("/api/links/{uid}/edit")
async def edit_link(uid: str, request: Request, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    if uid not in LINKS: raise HTTPException(404, "کاربر یافت نشد")
    d = await request.json()
    days = int(d.get("days", 0) or 0)
    gb = float(d.get("gb", 0) or 0)

    if days > 0: LINKS[uid]["expiry_time"] = time.time() + (days * 86400)
    else: LINKS[uid].pop("expiry_time", None)
    if gb > 0: LINKS[uid]["data_limit"] = int(gb * 1024 * 1024 * 1024)
    else: LINKS[uid].pop("data_limit", None)

    LINKS[uid]["status"] = "active"
    save_links()
    # فقط حضور کاربر را در inbound تضمین می‌کنیم.
    if not await ensure_user_hot_async(uid):
        await sync_xray_config_async()
    return {"ok": True}

@app.post("/api/links/{uid}/extend")
async def extend_link(uid: str, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    if uid not in LINKS: raise HTTPException(404)
    if "expiry_time" in LINKS[uid] and LINKS[uid]["expiry_time"] > time.time(): LINKS[uid]["expiry_time"] += 30 * 86400
    else: LINKS[uid]["expiry_time"] = time.time() + 30 * 86400
    LINKS[uid]["status"] = "active"
    save_links()
    if not await ensure_user_hot_async(uid):
        await sync_xray_config_async()
    return {"ok": True}

@app.post("/api/links/{uid}/reset")
async def reset_traffic(uid: str, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    if uid not in LINKS: raise HTTPException(404)
    user_traffic[uid] = 0
    LINKS[uid]["status"] = "active"
    await save_stats_async(); save_links()
    if not await ensure_user_hot_async(uid):
        await sync_xray_config_async()
    return {"ok": True}

@app.post("/api/cleanup")
async def cleanup_users(token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    global LINKS
    LINKS = {uid: info for uid, info in LINKS.items() if info.get("status") != "expired"}
    save_links(); await sync_xray_config_async(); return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    if uid == MASTER_UUID: raise HTTPException(403, "کاربر اصلی قابل حذف نیست")
    LINKS.pop(uid, None); save_links(); await remove_user_hot_async(uid); return {"ok": True}

@app.post("/api/change-password")
async def change_pass(request: Request, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    global PASS_HASH; d = await request.json()
    if hashlib.sha256(d.get("current","").encode()).hexdigest() != PASS_HASH: raise HTTPException(403, "رمز فعلی اشتباه است")
    PASS_HASH = hashlib.sha256(d.get("new","").encode()).hexdigest(); return {"ok": True}

@app.get("/api/backup")
async def backup_data(token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    backup = {"links": LINKS, "stats": {"total_unique_ips": list(total_unique_ips), "bytes": stats["bytes"], "start": stats["start"], "user_traffic": user_traffic}}
    return Response(content=json.dumps(backup, indent=2), media_type="application/json", headers={"Content-Disposition": "attachment; filename=xray_backup.json"})

@app.post("/api/restore")
async def restore_data(request: Request, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    global LINKS, total_unique_ips, stats, user_traffic
    try:
        data = await request.json()
        if "links" in data: LINKS = data["links"]
        if "stats" in data:
            s = data["stats"]
            total_unique_ips = set(s.get("total_unique_ips", []))
            stats["bytes"] = s.get("bytes", 0); stats["start"] = s.get("start", time.time())
            user_traffic = s.get("user_traffic", {})
        save_links(); await save_stats_async(); await sync_xray_config_async()
        return {"ok": True}
    except: raise HTTPException(400, "Invalid Backup")

# ── Subscription Link & HTML Page ────────────────────────
@app.get("/sub/{sid}")
async def subscription(sid: str, request: Request):
    user_uid, user_info = None, None
    for uid, info in LINKS.items():
        if info.get("short_id") == sid: user_uid, user_info = uid, info; break
            
    if not user_info: return HTMLResponse("<h1>404 Not Found</h1>", status_code=404)

    domain = get_domain(request)
    links = make_links(user_uid, domain, user_info["label"], sid, user_info.get("clean_ip", ""))

    user_agent = request.headers.get("user-agent", "").lower()
    is_clash = "clash" in user_agent or "meta" in user_agent
    is_browser = any(b in user_agent for b in ["mozilla", "chrome", "safari", "opera", "edge", "firefox"])

    if is_clash:
        clash_conf = make_clash_config(user_uid, domain, user_info["label"], user_info.get("clean_ip", ""))
        return PlainTextResponse(clash_conf, media_type="text/yaml")

    used_traffic = user_traffic.get(user_uid, 0)
    data_limit = user_info.get("data_limit", 0)
    remaining_data = (data_limit - used_traffic) if data_limit else 0
    expiry_time = user_info.get("expiry_time", 0)
    remaining_days = max(0, int((expiry_time - time.time()) / 86400)) if expiry_time else 0
    status = user_info.get("status", "active")

    if not is_browser:
        headers = {"Subscription-Userinfo": f"upload=0; download={used_traffic}; total={data_limit if data_limit else 0}; expire={expiry_time if expiry_time else 0}"}
        vol_str = fmt_bytes(remaining_data) if data_limit else "نامحدود"
        days_str = f"{remaining_days} روز" if expiry_time else "نامحدود"
        dummy_config = f"vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1#📊 حجم: {vol_str} | ⏳ زمان: {days_str}"
        final_sub_base64 = base64.b64encode("\n".join([links['ws'], dummy_config]).encode()).decode()
        return PlainTextResponse(final_sub_base64, media_type="text/plain", headers=headers)

    import urllib.parse
    html_content = SUB_HTML.replace("__LABEL__", user_info['label']) \
        .replace("__BADGE_CLASS__", 'badge-active' if status=='active' else 'badge-expired') \
        .replace("__STATUS_TEXT__", '🟢 فعال' if status=='active' else '🔴 منقضی شده') \
        .replace("__SUB_LINK_URL__", urllib.parse.quote(links['sub_link'], safe='')) \
        .replace("__SUB_LINK__", links['sub_link']) \
        .replace("__USED__", fmt_bytes(used_traffic)) \
        .replace("__REMAIN__", fmt_bytes(remaining_data) if data_limit else 'نامحدود') \
        .replace("__TOTAL__", fmt_bytes(data_limit) if data_limit else 'نامحدود') \
        .replace("__DAYS__", str(remaining_days) if expiry_time else 'نامحدود') \
        .replace("__LINK_WS__", links['ws'])

    return HTMLResponse(html_content)

# ── صفحات HTML ادمین ──────────────────────────────────────
# طراحی مدرن «گلس/تاریک» — تنها پروتکل: VLESS + WS + TLS
_THEME_CSS = r"""
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg0:#0b1020;--bg1:#0f1530;--card:rgba(255,255,255,.045);--card2:rgba(255,255,255,.07);--stroke:rgba(255,255,255,.10);--text:#eaf0ff;--muted:#9aa6c8;--accent:#7c8cff;--accent2:#a779ff;--cyan:#36d6e7;--green:#34d399;--red:#fb7185;--yellow:#fbbf24}
.light{--bg0:#eef2ff;--bg1:#f6f8ff;--card:rgba(255,255,255,.85);--card2:#fff;--stroke:rgba(20,30,80,.10);--text:#172036;--muted:#5b6a8c;--accent:#5b6bff;--accent2:#8b5cf6;--cyan:#0891b2;--green:#059669;--red:#e11d48;--yellow:#d97706}
body{font-family:'Vazirmatn',sans-serif;color:var(--text);min-height:100vh;background:radial-gradient(1200px 600px at 90% -10%,rgba(124,140,255,.18),transparent 60%),radial-gradient(1000px 500px at -10% 110%,rgba(167,121,255,.16),transparent 55%),linear-gradient(160deg,var(--bg0),var(--bg1));background-attachment:fixed}
.glass{background:var(--card);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border:1px solid var(--stroke);border-radius:18px}
::-webkit-scrollbar{width:9px;height:9px}::-webkit-scrollbar-thumb{background:rgba(140,150,200,.35);border-radius:8px}
"""

LOGIN_HTML = r"""<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ورود — پنل XRAY</title><link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet"><style>__THEME__
body{display:flex;align-items:center;justify-content:center;padding:20px}
.card{padding:44px 38px;width:100%;max-width:410px;box-shadow:0 30px 80px rgba(0,0,0,.45)}
.logo{text-align:center;margin-bottom:30px}
.logo-icon{width:70px;height:70px;background:linear-gradient(135deg,var(--accent),var(--accent2));border-radius:20px;display:inline-flex;align-items:center;justify-content:center;font-size:32px;margin-bottom:14px;box-shadow:0 12px 30px rgba(124,140,255,.45)}
.logo h1{font-size:23px;font-weight:800;letter-spacing:.5px}
.logo p{color:var(--muted);font-size:13px;margin-top:4px}
label{display:block;color:var(--muted);font-size:13px;margin-bottom:7px}
input{width:100%;padding:13px 16px;background:var(--card2);border:1px solid var(--stroke);border-radius:13px;color:var(--text);font-family:inherit;font-size:15px;outline:none;transition:.2s}
input:focus{border-color:var(--accent);box-shadow:0 0 0 4px rgba(124,140,255,.15)}
.btn{width:100%;padding:14px;background:linear-gradient(135deg,var(--accent),var(--accent2));border:none;border-radius:13px;color:#fff;font-family:inherit;font-size:16px;font-weight:700;cursor:pointer;margin-top:24px;transition:.2s}
.btn:hover{transform:translateY(-2px);box-shadow:0 14px 34px rgba(124,140,255,.45)}
.err{color:var(--red);font-size:13px;text-align:center;margin-top:14px;min-height:20px}</style></head>
<body><div class="card glass"><div class="logo"><div class="logo-icon">⚡</div><h1>پنل XRAY</h1><p>VLESS · WebSocket · TLS</p></div><div><label>رمز عبور</label><input type="password" id="pass" placeholder="رمز عبور را وارد کنید" onkeydown="if(event.key==='Enter')login()"></div><button class="btn" onclick="login()">ورود به پنل</button><div class="err" id="err"></div></div>
<script>async function login(){const p=document.getElementById('pass').value;const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p})});if(r.ok)location.href='__ADMIN_URL__';else document.getElementById('err').textContent='رمز عبور اشتباه است'}</script></body></html>""".replace("__THEME__", _THEME_CSS)

SUB_HTML = r"""<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>پنل کاربری</title><link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet"><style>__THEME__
body{display:flex;justify-content:center;padding:22px}
.wrap{max-width:560px;width:100%}
.head{text-align:center;margin-bottom:20px}
.head .ic{width:62px;height:62px;border-radius:18px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:inline-flex;align-items:center;justify-content:center;font-size:28px;margin-bottom:10px;box-shadow:0 12px 30px rgba(124,140,255,.4)}
.head h1{font-size:20px;font-weight:800}
.badge{display:inline-block;padding:5px 14px;border-radius:30px;font-size:12px;font-weight:700;margin-top:10px}
.badge-active{background:rgba(52,211,153,.16);color:var(--green);border:1px solid rgba(52,211,153,.35)}
.badge-expired{background:rgba(251,113,133,.16);color:var(--red);border:1px solid rgba(251,113,133,.35)}
.sponsor{display:flex;align-items:center;gap:12px;padding:13px 16px;margin:16px 0;text-decoration:none;color:var(--text)}
.sponsor .ic{font-size:20px}.sponsor b{display:block;font-size:13px}.sponsor span{font-size:11px;color:var(--accent);direction:ltr;font-weight:700}
.qr{padding:18px;text-align:center;margin-bottom:18px}
.qr img{width:210px;border-radius:14px;background:#fff;padding:8px}
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:13px;margin-bottom:18px}
.cell{padding:18px;text-align:center}
.cell .v{font-size:21px;font-weight:800}.cell .l{font-size:12px;color:var(--muted);margin-top:4px}
.cfg{padding:16px;margin-bottom:14px}
.cfg .t{font-size:13px;font-weight:700;color:var(--accent);margin-bottom:8px}
.cfg .val{font-size:11px;color:var(--muted);word-break:break-all;direction:ltr;text-align:left;line-height:1.7;background:var(--card2);border:1px solid var(--stroke);border-radius:10px;padding:10px}
.btn{width:100%;padding:12px;border:none;border-radius:12px;color:#fff;font-family:inherit;font-size:13px;font-weight:700;cursor:pointer;margin-top:10px;transition:.2s}
.btn:hover{transform:translateY(-1px)}
.b-a{background:linear-gradient(135deg,var(--accent),var(--accent2))}.b-g{background:linear-gradient(135deg,var(--green),#10b981)}</style></head>
<body><div class="wrap">
<div class="head"><div class="ic">⚡</div><h1>__LABEL__</h1><div class="badge __BADGE_CLASS__">__STATUS_TEXT__</div></div>
<a class="sponsor glass" href="https://t.me/ZodProxy" target="_blank" rel="noopener"><span class="ic">📡</span><span style="flex:1"><b>کانفیگ‌های پرسرعت و آپدیت</b><span>@ZodProxy ←</span></span></a>
<div class="qr glass"><img src="https://api.qrserver.com/v1/create-qr-code/?size=210x210&data=__SUB_LINK_URL__"></div>
<div class="grid">
<div class="cell glass"><div class="v">__USED__</div><div class="l">📦 مصرف‌شده</div></div>
<div class="cell glass"><div class="v">__REMAIN__</div><div class="l">📊 باقی‌مانده</div></div>
<div class="cell glass"><div class="v">__TOTAL__</div><div class="l">📈 حجم کل</div></div>
<div class="cell glass"><div class="v">__DAYS__</div><div class="l">⏳ روز باقی‌مانده</div></div>
</div>
<div class="cfg glass"><div class="t">🚀 لینک اشتراک (Sub Link)</div><div class="val" id="sub">__SUB_LINK__</div><button class="btn b-g" onclick="cp('sub',this)">کپی لینک اشتراک</button></div>
<div class="cfg glass"><div class="t">🔗 VLESS + WS + TLS</div><div class="val" id="ws">__LINK_WS__</div><button class="btn b-a" onclick="cp('ws',this)">کپی کانفیگ</button></div>
</div>
<script>function cp(id,btn){navigator.clipboard.writeText(document.getElementById(id).textContent).then(function(){var o=btn.textContent;btn.textContent='کپی شد ✓';setTimeout(function(){btn.textContent=o},1800)})}</script></body></html>""".replace("__THEME__", _THEME_CSS)

PANEL_HTML = r"""<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>پنل XRAY</title><link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet"><style>__THEME__
body{display:flex}
.sidebar{width:230px;min-height:100vh;position:fixed;right:0;top:0;bottom:0;z-index:10;display:flex;flex-direction:column;padding:22px 0;background:var(--card);backdrop-filter:blur(16px);border-left:1px solid var(--stroke)}
.sb-logo{padding:0 22px 20px;border-bottom:1px solid var(--stroke);margin-bottom:14px}
.sb-logo h2{font-size:19px;font-weight:800;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.sb-logo p{font-size:11px;color:var(--muted);margin-top:3px}
.nav{display:flex;align-items:center;gap:11px;padding:12px 22px;cursor:pointer;color:var(--muted);font-size:14px;font-weight:600;transition:.15s;border-right:3px solid transparent}
.nav:hover{color:var(--text);background:var(--card2)}
.nav.active{color:var(--accent);background:linear-gradient(90deg,rgba(124,140,255,.16),transparent);border-right-color:var(--accent)}
.nav span:first-child{font-size:18px}
.sb-bottom{margin-top:auto;padding:16px 22px;border-top:1px solid var(--stroke);display:flex;flex-direction:column;gap:10px}
.gbtn{width:100%;padding:10px;background:var(--card2);border:1px solid var(--stroke);border-radius:11px;color:var(--muted);font-family:inherit;font-size:13px;cursor:pointer;transition:.15s}
.gbtn:hover{border-color:var(--accent);color:var(--accent)}
.main{margin-right:230px;flex:1;padding:30px;min-height:100vh}
.page{display:none}.page.active{display:block;animation:fade .3s ease}
@keyframes fade{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.ptitle{font-size:24px;font-weight:800;margin-bottom:24px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:26px}
.stat{padding:18px 20px;position:relative;overflow:hidden}
.stat .ic{font-size:20px;opacity:.9}
.stat .v{font-size:27px;font-weight:800;margin-top:6px;line-height:1.1}
.stat .l{font-size:12px;color:var(--muted);margin-top:5px}
.stat .d{font-size:11px;color:var(--muted);margin-top:2px}
.stat.hl{background:linear-gradient(135deg,rgba(124,140,255,.16),rgba(167,121,255,.10))}
.stat.hl .v{background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.stat canvas{position:absolute;left:10px;bottom:10px;width:70px;height:30px;opacity:.85}
.panel{padding:0;overflow:hidden;margin-bottom:20px}
.phead{padding:18px 22px;border-bottom:1px solid var(--stroke);display:flex;align-items:center;justify-content:space-between}
.phead h3{font-size:16px;font-weight:700}
.badd{padding:9px 18px;background:linear-gradient(135deg,var(--accent),var(--accent2));border:none;border-radius:11px;color:#fff;font-family:inherit;font-size:13px;font-weight:700;cursor:pointer;transition:.2s}
.badd:hover{transform:translateY(-1px);box-shadow:0 10px 24px rgba(124,140,255,.4)}
table{width:100%;border-collapse:collapse}
th{padding:12px 18px;text-align:right;font-size:12px;font-weight:700;color:var(--muted);border-bottom:1px solid var(--stroke)}
td{padding:14px 18px;font-size:13px;border-bottom:1px solid var(--stroke)}
tr:last-child td{border-bottom:none}tr:hover td{background:var(--card2)}
.pill{display:inline-block;padding:4px 10px;border-radius:20px;font-size:11px;font-weight:700}
.p-on{background:rgba(52,211,153,.16);color:var(--green)}
.p-off{background:rgba(154,166,200,.16);color:var(--muted)}
.p-exp{background:rgba(251,113,133,.16);color:var(--red)}
.p-y{background:rgba(251,191,36,.16);color:var(--yellow)}
.bsm{padding:6px 12px;border:1px solid var(--stroke);background:var(--card2);border-radius:9px;font-family:inherit;font-size:12px;cursor:pointer;transition:.15s;color:var(--muted);margin:2px}
.bsm:hover{border-color:var(--accent);color:var(--accent)}
.online-list{padding:20px}
.ucard{display:flex;align-items:center;gap:12px;padding:13px 16px;margin-bottom:10px;background:var(--card2);border:1px solid var(--stroke);border-radius:13px}
.ucard:last-child{margin-bottom:0}
.dot{width:10px;height:10px;border-radius:50%;background:var(--green);box-shadow:0 0 0 4px rgba(52,211,153,.18);animation:pulse 1.6s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.45}}
.ucard .nm{font-weight:700;font-size:13px;flex:1}.ucard .cf{font-size:11px;color:var(--muted)}
.overlay{position:fixed;inset:0;background:rgba(5,8,20,.6);backdrop-filter:blur(3px);z-index:100;display:none;align-items:center;justify-content:center;padding:16px}
.overlay.show{display:flex}
.modal{padding:28px;width:100%;max-width:480px;max-height:92vh;overflow-y:auto;box-shadow:0 30px 80px rgba(0,0,0,.5)}
.modal h3{font-size:18px;font-weight:800;margin-bottom:20px}
.fg{margin-bottom:15px}.fg label{display:block;font-size:13px;color:var(--muted);margin-bottom:6px}
.fg input{width:100%;padding:11px 14px;border:1px solid var(--stroke);border-radius:11px;background:var(--card2);color:var(--text);font-family:inherit;font-size:14px;outline:none;transition:.2s}
.fg input:focus{border-color:var(--accent);box-shadow:0 0 0 4px rgba(124,140,255,.13)}
.mfoot{display:flex;gap:10px;justify-content:flex-end;margin-top:22px}
.bok{padding:10px 20px;background:linear-gradient(135deg,var(--accent),var(--accent2));border:none;border-radius:11px;color:#fff;font-family:inherit;font-size:13px;font-weight:700;cursor:pointer}
.lbox{background:var(--card2);border:1px solid var(--stroke);border-radius:12px;padding:14px;margin-bottom:12px}
.lbox .lt{font-size:13px;font-weight:700;color:var(--accent);margin-bottom:8px}
.lval{font-size:11px;color:var(--muted);word-break:break-all;direction:ltr;text-align:left;line-height:1.7}
.scard{padding:24px;max-width:520px;margin-bottom:20px}.scard h3{font-size:16px;font-weight:700;margin-bottom:16px}
.logbox{background:#05070f;color:#5ef0a8;padding:16px;border-radius:12px;height:320px;overflow-y:auto;font-family:ui-monospace,monospace;font-size:12px;direction:ltr;text-align:left;border:1px solid var(--stroke)}
.mhead{display:none}
@media(max-width:820px){
.sidebar{width:100%;min-height:auto;flex-direction:row;padding:0;top:auto;border-left:none;border-top:1px solid var(--stroke)}
.sb-logo,.sb-bottom{display:none}
.nav{flex-direction:column;gap:3px;padding:9px 0;flex:1;justify-content:center;font-size:10px;border-right:none!important}
.nav.active{border-top:2px solid var(--accent);background:var(--card2)}
.main{margin-right:0;margin-bottom:66px;padding:16px;padding-top:70px}
.mhead{display:flex;justify-content:space-between;align-items:center;padding:12px 18px;position:fixed;top:0;left:0;right:0;z-index:20;background:var(--card);backdrop-filter:blur(16px);border-bottom:1px solid var(--stroke)}
.mhead h2{font-size:16px;font-weight:800;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
}</style></head>
<body>
<div class="mhead"><h2>⚡ پنل XRAY</h2><div><button class="gbtn" style="width:auto;padding:8px 12px" onclick="toggleTheme()" id="thm-m">☀️</button> <button class="gbtn" style="width:auto;padding:8px 12px;border-color:var(--red);color:var(--red)" onclick="logout()">خروج</button></div></div>
<div class="sidebar">
<div class="sb-logo"><h2>⚡ پنل XRAY</h2><p>VLESS · WS · TLS</p></div>
<div class="nav active" onclick="showPage('dashboard',this)"><span>📊</span><span>داشبورد</span></div>
<div class="nav" onclick="showPage('users',this)"><span>👥</span><span>کاربران</span></div>
<div class="nav" onclick="showPage('logs',this)"><span>📜</span><span>لاگ‌ها</span></div>
<div class="nav" onclick="showPage('settings',this)"><span>⚙️</span><span>تنظیمات</span></div>
<div class="sb-bottom"><button class="gbtn" onclick="toggleTheme()" id="thm-d">☀️ تم روشن</button><button class="gbtn" style="border-color:var(--red);color:var(--red)" onclick="logout()">خروج</button></div>
</div>
<div class="main">

<div class="page active" id="page-dashboard">
  <div class="ptitle">داشبورد</div>
  <div class="stats">
    <div class="stat glass hl"><div class="ic">🔌</div><div class="v" id="s-live">—</div><div class="l">اتصالات فعال (هم‌زمان)</div></div>
    <div class="stat glass hl"><div class="ic">🌐</div><div class="v" id="s-ips">—</div><div class="l">ایپی‌های آنلاین</div></div>
    <div class="stat glass hl"><div class="ic">🟢</div><div class="v" id="s-online">—</div><div class="l">کاربران آنلاین</div></div>
    <div class="stat glass"><div class="ic">👤</div><div class="v" id="s-total">—</div><div class="l">کل کاربران</div></div>
    <div class="stat glass"><div class="ic">⬇️</div><div class="v" id="s-dl">—</div><div class="l">سرعت دانلود</div><canvas id="sp-dl" width="70" height="30"></canvas></div>
    <div class="stat glass"><div class="ic">⬆️</div><div class="v" id="s-ul">—</div><div class="l">سرعت آپلود</div><canvas id="sp-ul" width="70" height="30"></canvas></div>
    <div class="stat glass"><div class="ic">🧠</div><div class="v" id="s-ram">—</div><div class="l">رم کانتینر</div><div class="d" id="s-ram-d">—</div><canvas id="sp-ram" width="70" height="30"></canvas></div>
    <div class="stat glass"><div class="ic">⚙️</div><div class="v" id="s-cpu">—</div><div class="l">پردازنده</div><div class="d" id="s-cpu-d">—</div><canvas id="sp-cpu" width="70" height="30"></canvas></div>
    <div class="stat glass"><div class="ic">📦</div><div class="v" id="s-bytes">—</div><div class="l">ترافیک Xray</div></div>
    <div class="stat glass"><div class="ic">🧮</div><div class="v" id="s-comb">—</div><div class="l">ترافیک کل (Xray + ریلوی)</div></div>
    <div class="stat glass"><div class="ic">💾</div><div class="v" id="s-disk">—</div><div class="l">دیسک کانتینر</div></div>
    <div class="stat glass"><div class="ic">🌍</div><div class="v" id="s-hist">—</div><div class="l">کل ایپی‌ها (تاریخی)</div></div>
  </div>
  <div class="panel glass">
    <div class="phead"><h3>🟢 کاربران آنلاین <span class="pill p-on" id="on-badge" style="margin-right:8px"></span></h3></div>
    <div class="online-list" id="online-list"><div style="color:var(--muted);text-align:center;padding:14px">در حال بارگذاری...</div></div>
  </div>
</div>

<div class="page" id="page-users">
  <div class="ptitle">کاربران</div>
  <div class="panel glass"><div class="phead"><h3>لیست کاربران</h3><button class="badd" onclick="openAdd()">+ کاربر جدید</button></div>
  <table><thead><tr><th>نام</th><th>UUID</th><th>تاریخ</th><th>مصرف</th><th>وضعیت</th><th>عملیات</th></tr></thead><tbody id="utbody"></tbody></table></div>
</div>

<div class="page" id="page-logs">
  <div class="ptitle">لاگ‌های سیستم</div>
  <div class="panel glass"><div class="phead"><h3>آخرین لاگ‌های Xray</h3><button class="bsm" onclick="loadLogs()">🔄 بروزرسانی</button></div><div style="padding:18px"><div class="logbox" id="logbox">در حال بارگذاری...</div></div></div>
</div>

<div class="page" id="page-settings">
  <div class="ptitle">تنظیمات</div>
  <div class="scard glass"><h3>🔑 تغییر رمز عبور</h3><div class="fg"><label>رمز فعلی</label><input type="password" id="cp-old"></div><div class="fg"><label>رمز جدید</label><input type="password" id="cp-new"></div><button class="bok" style="width:100%" onclick="changePass()">تغییر رمز عبور</button><div id="cp-msg" style="margin-top:10px;font-size:13px;text-align:center"></div></div>
  <div class="scard glass"><h3>💾 بکاپ و بازیابی</h3><button class="bok" style="width:100%;margin-bottom:10px" onclick="dlBackup()">⬇️ دانلود بکاپ</button><input type="file" id="rfile" accept=".json" style="display:none"><button class="gbtn" style="padding:11px" onclick="document.getElementById('rfile').click()">⬆️ آپلود و بازیابی</button></div>
  <div class="scard glass"><h3>🗑️ پاکسازی</h3><button class="bok" style="width:100%;background:linear-gradient(135deg,var(--red),#e11d48)" onclick="cleanup()">حذف کاربران منقضی‌شده</button></div>
  <div class="scard glass"><h3>🚂 تست اتصال ریلوی</h3><p style="font-size:12px;color:var(--muted);margin-bottom:10px">برای دیباگ متریک‌های رم/ترافیک ریلوی. بعد از ست‌کردن RAILWAY_API_TOKEN سرویس را Redeploy کنید.</p><button class="bok" style="width:100%" onclick="testRailway()">تست اتصال</button><pre id="rw-res" style="margin-top:10px;font-size:12px;background:var(--card2);border:1px solid var(--stroke);border-radius:10px;padding:10px;white-space:pre-wrap;word-break:break-all;display:none;max-height:380px;overflow:auto;direction:ltr;text-align:left"></pre></div>
</div>
</div>

<div class="overlay" id="add-modal"><div class="modal glass"><h3>کاربر جدید</h3>
<div class="fg"><label>نام کاربر</label><input id="n-label" placeholder="مثلاً: علی"></div>
<div class="fg"><label>UUID (اختیاری)</label><input id="n-uuid" placeholder="خالی = ساخت خودکار"></div>
<div class="fg"><label>کد ساب‌لینک ۷رقمی (اختیاری)</label><input id="n-sid" placeholder="خالی = ساخت خودکار" maxlength="7"></div>
<div class="fg"><label>ایپی تمیز (اختیاری)</label><input id="n-cip" placeholder="مثلاً: 1.1.1.1"></div>
<div style="display:flex;gap:10px"><div class="fg" style="flex:1"><label>انقضا (روز)</label><input type="number" id="n-days" value="0" placeholder="0 = نامحدود"></div><div class="fg" style="flex:1"><label>حجم (GB)</label><input type="number" id="n-gb" value="0" placeholder="0 = نامحدود"></div></div>
<div class="mfoot"><button class="bsm" onclick="closeAdd()">انصراف</button><button class="bok" onclick="createUser()">ساخت کاربر</button></div></div></div>

<div class="overlay" id="edit-modal"><div class="modal glass"><h3>ویرایش کاربر</h3><input type="hidden" id="e-uid">
<div class="fg"><label>نام کاربر</label><input id="e-label" disabled></div>
<div style="display:flex;gap:10px"><div class="fg" style="flex:1"><label>انقضای جدید (روز)</label><input type="number" id="e-days" value="0" placeholder="0 = نامحدود"></div><div class="fg" style="flex:1"><label>حجم جدید (GB)</label><input type="number" id="e-gb" value="0" placeholder="0 = نامحدود"></div></div>
<div style="text-align:center;margin-top:8px"><button class="bsm" style="border-color:var(--yellow);color:var(--yellow)" onclick="resetTraffic()">🔄 ریست ترافیک</button></div>
<div class="mfoot"><button class="bsm" onclick="closeEdit()">انصراف</button><button class="bok" onclick="saveEdit()">ذخیره</button></div></div></div>

<div class="overlay" id="link-modal"><div class="modal glass"><h3 id="lm-title">کانفیگ‌ها</h3>
<div class="lbox"><div class="lt">🚀 لینک اشتراک</div><div class="lval" id="lk-sub">—</div><button class="bsm" style="border-color:var(--accent);color:var(--accent);margin-top:8px" onclick="cp('lk-sub')">کپی</button></div>
<div class="lbox"><div class="lt">🔗 VLESS + WS + TLS</div><div class="lval" id="lk-ws">—</div><button class="bsm" style="margin-top:8px" onclick="cp('lk-ws')">کپی</button></div>
<div id="lk-qr" style="text-align:center;margin:8px 0"></div>
<div class="mfoot"><button class="bok" onclick="closeLinks()">بستن</button></div></div></div>

<script>
var allUsers={},hist={dl:[],ul:[],ram:[],cpu:[]};
function toggleTheme(){document.body.classList.toggle('light');var l=document.body.classList.contains('light');var i=l?'🌙 تم تاریک':'☀️ تم روشن';var d=document.getElementById('thm-d');if(d)d.textContent=i;var m=document.getElementById('thm-m');if(m)m.textContent=l?'🌙':'☀️';try{localStorage.setItem('theme',l?'light':'dark')}catch(e){}}
if((function(){try{return localStorage.getItem('theme')}catch(e){return null}})()==='light')document.body.classList.add('light');
function fmtBytes(b){if(!b||b<1024)return(b||0)+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';if(b<1073741824)return(b/1048576).toFixed(2)+' MB';return(b/1073741824).toFixed(2)+' GB';}
function fmtSpeed(b){if(!b||b<1024)return(b||0)+' B/s';if(b<1048576)return(b/1024).toFixed(1)+' KB/s';if(b<1073741824)return(b/1048576).toFixed(2)+' MB/s';return(b/1073741824).toFixed(2)+' GB/s';}
function spark(id,arr,color){var c=document.getElementById(id);if(!c)return;var ctx=c.getContext('2d');var w=c.width,h=c.height;ctx.clearRect(0,0,w,h);if(arr.length<2)return;var mx=Math.max.apply(null,arr)||1;ctx.beginPath();for(var i=0;i<arr.length;i++){var x=i/(arr.length-1)*w;var y=h-(arr[i]/mx)*(h-3)-2;i?ctx.lineTo(x,y):ctx.moveTo(x,y);}ctx.strokeStyle=color;ctx.lineWidth=2;ctx.lineJoin='round';ctx.stroke();ctx.lineTo(w,h);ctx.lineTo(0,h);ctx.closePath();ctx.fillStyle=color.replace('rgb','rgba').replace(')',',.15)');ctx.fill();}
function push(a,v){a.push(v);if(a.length>30)a.shift();}
function showPage(n,e){document.querySelectorAll('.page').forEach(function(p){p.classList.remove('active')});document.querySelectorAll('.nav').forEach(function(x){x.classList.remove('active')});document.getElementById('page-'+n).classList.add('active');e.classList.add('active');if(n==='users')loadUsers();if(n==='logs')loadLogs();}
async function logout(){await fetch('/api/logout',{method:'POST'});location.href='__LOGIN_URL__';}
async function loadStats(){try{const r=await fetch('/api/stats',{credentials:'include'});if(r.status===401){location.href='__LOGIN_URL__';return}const d=await r.json();
document.getElementById('s-live').textContent=d.live_connections;
document.getElementById('s-ips').textContent=d.active_ips;
document.getElementById('s-online').textContent=d.active_uuids;
document.getElementById('s-total').textContent=d.total_users;
document.getElementById('s-dl').textContent=fmtSpeed(d.dl_speed);
document.getElementById('s-ul').textContent=fmtSpeed(d.ul_speed);
document.getElementById('s-ram').textContent=d.ram+'%';
document.getElementById('s-ram-d').textContent=d.ram_used_mb+' / '+d.ram_limit_mb+' MB';
document.getElementById('s-cpu').textContent=d.cpu+'%';
document.getElementById('s-cpu-d').textContent=(d.cpu_cores||0)+' هسته';
document.getElementById('s-bytes').textContent=fmtBytes(d.bytes);
document.getElementById('s-comb').textContent=fmtBytes(d.combined_bytes);
document.getElementById('s-disk').textContent=d.disk_used_gb+' / '+d.disk_total_gb+' GB';
document.getElementById('s-hist').textContent=d.total_connected;
push(hist.dl,d.dl_speed);push(hist.ul,d.ul_speed);push(hist.ram,d.ram);push(hist.cpu,d.cpu);
spark('sp-dl',hist.dl,'rgb(52,211,153)');spark('sp-ul',hist.ul,'rgb(124,140,255)');spark('sp-ram',hist.ram,'rgb(167,121,255)');spark('sp-cpu',hist.cpu,'rgb(54,214,231)');
var cfgs=d.active_configs||[];document.getElementById('on-badge').textContent=(d.active_uuids||0)+' آنلاین';
var ol=document.getElementById('online-list');
if(!cfgs.length){ol.innerHTML='<div style="color:var(--muted);text-align:center;padding:14px">هیچ کاربری آنلاین نیست</div>';}
else{ol.innerHTML=cfgs.map(function(it){return '<div class="ucard"><span class="dot"></span><span class="nm">'+it.label+'</span><span class="cf">'+it.config+'</span></div>';}).join('');}
}catch(e){}}
async function loadUsers(){try{const r=await fetch('/api/links',{credentials:'include'});if(r.status===401){location.href='__LOGIN_URL__';return}const d=await r.json();const tb=document.getElementById('utbody');if(!d.links.length){tb.innerHTML='<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--muted)">کاربری وجود ندارد</td></tr>';return;}allUsers={};tb.innerHTML=d.links.map(function(u){allUsers[u.uuid]=u;var st='<span class="pill p-on">🟢 آنلاین</span>';if(u.status==='expired')st='<span class="pill p-exp">منقضی</span>';else if(u.status==='blocked')st='<span class="pill p-exp">مسدود</span>';else if(!u.online)st='<span class="pill p-off">آفلاین</span>';var lim='';if(u.data_limit>0)lim+='<span class="pill p-y">باقی: '+fmtBytes(u.remaining_data)+'</span> ';if(u.remaining_days>0)lim+='<span class="pill p-y">'+u.remaining_days+' روز</span>';return '<tr><td><b>'+u.label+'</b>'+(lim?'<br><span style="font-size:11px">'+lim+'</span>':'')+'</td><td><span style="font-size:10px;color:var(--muted)">'+u.uuid.substring(0,8)+'…</span></td><td>'+u.created_at+'</td><td>'+fmtBytes(u.used_traffic)+'</td><td>'+st+'</td><td><button class="bsm" onclick="showLinks(\''+u.uuid+'\')">🔗</button><button class="bsm" onclick="extendUser(\''+u.uuid+'\')">➕۳۰</button><button class="bsm" onclick="editUser(\''+u.uuid+'\')">✏️</button><button class="bsm" style="border-color:var(--red);color:var(--red)" onclick="delUser(\''+u.uuid+'\')">🗑️</button></td></tr>';}).join('');}catch(e){}}
async function loadLogs(){try{const r=await fetch('/api/logs');const d=await r.json();document.getElementById('logbox').innerHTML=(d.logs||[]).join('<br>')||'لاگی وجود ندارد.';}catch(e){}}
function openAdd(){document.getElementById('add-modal').classList.add('show');}function closeAdd(){document.getElementById('add-modal').classList.remove('show');}
async function createUser(){const b={label:document.getElementById('n-label').value||'کاربر',uuid:document.getElementById('n-uuid').value,short_id:document.getElementById('n-sid').value,clean_ip:document.getElementById('n-cip').value,days:document.getElementById('n-days').value,gb:document.getElementById('n-gb').value};const r=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});const d=await r.json();d.label=b.label;closeAdd();['n-label','n-uuid','n-sid','n-cip'].forEach(function(i){document.getElementById(i).value='';});loadUsers();showLinks(d.uuid,d);}
function editUser(uid){var u=allUsers[uid];if(!u)return;document.getElementById('e-uid').value=uid;document.getElementById('e-label').value=u.label;document.getElementById('e-days').value=0;document.getElementById('e-gb').value=0;document.getElementById('edit-modal').classList.add('show');}
function closeEdit(){document.getElementById('edit-modal').classList.remove('show');}
async function saveEdit(){const uid=document.getElementById('e-uid').value;const b={days:document.getElementById('e-days').value,gb:document.getElementById('e-gb').value};const r=await fetch('/api/links/'+uid+'/edit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});if(r.ok){closeEdit();loadUsers();}}
async function extendUser(uid){if(!confirm('۳۰ روز اضافه شود؟'))return;const r=await fetch('/api/links/'+uid+'/extend',{method:'POST'});if(r.ok)loadUsers();}
async function resetTraffic(){const uid=document.getElementById('e-uid').value;if(!confirm('ترافیک صفر شود؟'))return;const r=await fetch('/api/links/'+uid+'/reset',{method:'POST'});if(r.ok){closeEdit();loadUsers();}}
async function delUser(uid){if(!confirm('حذف شود؟'))return;await fetch('/api/links/'+uid,{method:'DELETE'});loadUsers();}
async function cleanup(){if(!confirm('کاربران منقضی‌شده حذف شوند؟'))return;await fetch('/api/cleanup',{method:'POST'});loadUsers();alert('پاکسازی شد ✓');}
async function testRailway(){var box=document.getElementById('rw-res');box.style.display='block';box.textContent='در حال تست...';try{const r=await fetch('/api/railway-test');box.textContent=JSON.stringify(await r.json(),null,2);}catch(e){box.textContent='خطا: '+e;}}
function showLinks(uid,fresh){var u=fresh||allUsers[uid];if(!u)return;document.getElementById('lm-title').textContent='کانفیگ‌های '+u.label;document.getElementById('lk-sub').textContent=u.sub_link;document.getElementById('lk-ws').textContent=u.ws;document.getElementById('lk-qr').innerHTML='<img style="width:170px;border-radius:12px;background:#fff;padding:6px" src="https://api.qrserver.com/v1/create-qr-code/?size=170x170&data='+encodeURIComponent(u.sub_link)+'">';document.getElementById('link-modal').classList.add('show');}
function closeLinks(){document.getElementById('link-modal').classList.remove('show');}
function cp(id){navigator.clipboard.writeText(document.getElementById(id).textContent);alert('کپی شد ✓');}
async function changePass(){const r=await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current:document.getElementById('cp-old').value,new:document.getElementById('cp-new').value})});var m=document.getElementById('cp-msg');if(r.ok){m.style.color='var(--green)';m.textContent='رمز تغییر کرد ✓';}else{m.style.color='var(--red)';m.textContent='رمز فعلی اشتباه است';}}
function dlBackup(){window.location.href='/api/backup';}
document.getElementById('rfile').addEventListener('change',async function(e){const f=e.target.files[0];if(!f)return;if(!confirm('بازیابی انجام شود؟ اطلاعات فعلی جایگزین می‌شود.'))return;const t=await f.text();try{const r=await fetch('/api/restore',{method:'POST',headers:{'Content-Type':'application/json'},body:t});if(r.ok){alert('بازیابی شد ✓');loadUsers();}else alert('فایل نامعتبر.');}catch(err){alert('خطا در خواندن فایل.');}});
loadStats();setInterval(loadStats,5000);
</script>
</body></html>""".replace("__THEME__", _THEME_CSS)

# ── Telegram Bot (Webhook) ───────────────────────────────
bot_router = APIRouter()
bot_state = {}

async def tg_request(method: str, payload: dict):
    global tg_client
    if not BOT_TOKEN or not tg_client: return None
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
    try:
        r = await tg_client.post(url, json=payload, timeout=5.0)
        return r.json()
    except:
        return None

async def send_message(chat_id: str, text: str, reply_markup=None):
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
    if reply_markup: payload["reply_markup"] = reply_markup
    await tg_request("sendMessage", payload)

async def edit_message(chat_id: str, message_id: str, text: str, reply_markup=None):
    payload = {"chat_id": chat_id, "message_id": message_id, "text": text, "parse_mode": "HTML"}
    if reply_markup: payload["reply_markup"] = reply_markup
    await tg_request("editMessageText", payload)

def main_menu():
    return {"inline_keyboard": [
        [{"text": "📊 آمار سرور", "callback_data": "stats"}, {"text": "👥 لیست کاربران", "callback_data": "users"}],
        [{"text": "➕ ساخت کاربر جدید", "callback_data": "new_user"}]
    ]}

@bot_router.post("/bot_webhook")
async def bot_webhook(req: Request):
    if not BOT_TOKEN: return {"ok": False}
    # تایید اینکه درخواست واقعا از سرور تلگرام می‌آید، نه یک درخواست جعلی از بیرون
    if req.headers.get("x-telegram-bot-api-secret-token") != WEBHOOK_SECRET:
        return {"ok": False}
    try:
        data = await req.json()
    except Exception:
        return {"ok": False}

    try:
        if "callback_query" in data:
            cq = data["callback_query"]
            chat_id = cq["message"]["chat"]["id"]
            user_id = cq["from"]["id"]
            msg_id = cq["message"]["message_id"]
            data_str = cq["data"]

            if str(user_id) != ADMIN_CHAT_ID: return {"ok": False}
            await tg_request("answerCallbackQuery", {"callback_query_id": cq["id"]})

            if data_str == "menu":
                await edit_message(chat_id, msg_id, "💡 <b>منوی مدیریت پنل XRAY</b>\nیکی از گزینه‌ها را انتخاب کنید:", main_menu())
            elif data_str == "stats":
                active_configs = build_active_configs()
                configs_text = format_active_configs_text(active_configs)
                total_active_ips = sum(it["ip_count"] for it in active_configs)
                text = (
                    "📊 <b>آمار زنده سرور</b>\n\n"
                    f"👤 کل کاربران: <b>{len(LINKS)}</b>\n"
                    f"🟢 آنلاین هم‌اکنون: <b>{total_active_ips}</b>\n"
                    f"🌐 کل ایپی‌های وصل شده: <b>{len(total_unique_ips)}</b>\n"
                    f"📦 ترافیک کل: <b>{fmt_bytes(stats['bytes'])}</b>\n"
                    f"⬇️ سرعت دانلود: <b>{fmt_speed(stats.get('dl_speed', 0))}</b>\n"
                    f"⬆️ سرعت آپلود: <b>{fmt_speed(stats.get('ul_speed', 0))}</b>\n\n"
                    f"🧠 مصرف RAM: <b>{sys_info['ram']}%</b>\n"
                    f"⚙️ مصرف CPU: <b>{sys_info['cpu']}%</b>\n"
                    f"⏱️ آپتایم: <b>{uptime_str()}</b>\n\n"
                    f"🔌 <b>کانفیگ‌های آنلاین:</b>\n{configs_text}"
                )
                await edit_message(chat_id, msg_id, text, main_menu())
            elif data_str == "users":
                if not LINKS:
                    text = "👥 <b>لیست کاربران</b>\n\nکاربری یافت نشد."
                else:
                    text = "👥 <b>لیست کاربران (۲۰ نفر اخیر)</b>\n\n"
                    for uid, info in list(LINKS.items())[-20:]:
                        status = "🟢" if uid in user_last_active else "⚪️"
                        text += f"{status} <b>{info['label']}</b> | {fmt_bytes(user_traffic.get(uid, 0))}\n"
                await edit_message(chat_id, msg_id, text, main_menu())
            elif data_str == "new_user":
                bot_state[chat_id] = "awaiting_name"
                cancel_btn = {"inline_keyboard": [[{"text": "❌ انصراف", "callback_data": "menu"}]]}
                await send_message(chat_id, "➕ <b>ساخت کاربر جدید</b>\n\nنام کاربر جدید را وارد کنید (مثلاً: علی):", cancel_btn)

        elif "message" in data:
            msg = data["message"]
            chat_id = msg["chat"]["id"]
            user_id = msg["from"]["id"]
            text = msg.get("text", "")

            if str(user_id) != ADMIN_CHAT_ID: return {"ok": False}

            if text == "/start":
                bot_state.pop(chat_id, None)
                await send_message(chat_id, "💡 <b>به ربات مدیریت پنل خوش آمدید!</b>\nیکی از گزینه‌ها را انتخاب کنید:", main_menu())
            elif bot_state.get(chat_id) == "awaiting_name":
                label = sanitize_label(text.strip())
                if not label:
                    await send_message(chat_id, "نام نمی‌تواند خالی باشد. دوباره وارد کنید:")
                    return {"ok": True}

                uid = str(uuid.uuid4())
                short_id = secrets.token_hex(4)[:7]
                info = {
                    "label": label,
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
                    "status": "active",
                    "short_id": short_id,
                    "clean_ip": "",
                }

                LINKS[uid] = info
                save_links()
                if not await add_user_hot_async(uid):
                    await sync_xray_config_async()

                domain = PUBLIC_HOST or "your-domain.com"
                sub_link = f"https://{domain}/sub/{short_id}"

                bot_state.pop(chat_id, None)
                await send_message(chat_id, f"✅ <b>کاربر با موفقیت ساخته شد!</b>\n\n👤 نام: <b>{label}</b>\n🔗 لینک ساب (برای v2rayNG):\n<code>{sub_link}</code>", main_menu())
    except Exception as e:
        log_err(f"bot_webhook: {e}")

    return {"ok": True}

async def set_telegram_webhook(domain: str):
    if not BOT_TOKEN or not ADMIN_CHAT_ID: return
    hook_url = f"https://{domain}/bot_webhook"
    await tg_request("setWebhook", {"url": hook_url, "secret_token": WEBHOOK_SECRET, "allowed_updates": ["message", "callback_query"]})
    await send_message(ADMIN_CHAT_ID, "🤖 <b>ربات مدیریت با موفقیت فعال شد!</b>\nپنل آماده دستورات است.", main_menu())

app.include_router(bot_router)

@app.get("/" + ADMIN_PATH + "/login", response_class=HTMLResponse)
async def login_page(): 
    return HTMLResponse(LOGIN_HTML.replace("__ADMIN_URL__", "/" + ADMIN_PATH))

@app.get("/" + ADMIN_PATH, response_class=HTMLResponse)
async def panel_page(token: Optional[str] = Cookie(None)):
    if not auth_check(token): return RedirectResponse("/" + ADMIN_PATH + "/login")
    html = PANEL_HTML.replace("__LOGIN_URL__", "/" + ADMIN_PATH + "/login")
    return HTMLResponse(html)

@app.get("/")
async def root(): return Response(content=b"OK", media_type="text/plain")

@app.get("/health")
async def health(): return {"status": "ok", "connections": len(user_last_active)}

if __name__ == "__main__":
    import logging; logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    uvicorn.run("panel:app", host="0.0.0.0", port=PORT, reload=False, log_level="warning")
