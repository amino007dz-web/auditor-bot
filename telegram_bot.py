import os, sys, json, time, logging, threading, re, tempfile, zipfile
from concurrent.futures import ThreadPoolExecutor
from difflib import unified_diff
sys.path.insert(0, os.path.dirname(__file__))

logger = logging.getLogger(__name__)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

WEB_UI_URL = os.environ.get("WEB_UI_URL", "https://auditor-bot.onrender.com")
GITHUB_RE = re.compile(r"github\.com/([^/\s]+)/([^/\s]+)")
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")
EXTENSIONS = {".sol": "solidity", ".vy": "vyper", ".move": "move", ".clsp": "chialisp", ".clib": "chialisp"}
MAX_WORKERS = 4
STATS_FILE = os.path.join(os.path.dirname(__file__), "bot_stats.json")
CHAIN_EXPLORERS = {
    "etherscan": {"api": "https://api.etherscan.io/api", "key_var": "ETHERSCAN_API_KEY"},
    "bscscan": {"api": "https://api.bscscan.com/api", "key_var": "BSCSCAN_API_KEY"},
    "polygonscan": {"api": "https://api.polygonscan.com/api", "key_var": "POLYGONSCAN_API_KEY"},
    "arbiscan": {"api": "https://api.arbiscan.io/api", "key_var": "ARBISCAN_API_KEY"},
    "snowtrace": {"api": "https://api.snowtrace.io/api", "key_var": "SNOWTRACE_API_KEY"},
}
SOURCE_EXTS = {".sol", ".vy", ".move", ".clsp", ".clib", ".rs", ".py"}


class RateLimiter:
    def __init__(self, max_requests: int = 5, window: int = 60):
        self.max = max_requests
        self.window = window
        self._requests: dict = {}
        self._lock = threading.Lock()

    def allow(self, user_id: int) -> bool:
        import time
        now = time.time()
        with self._lock:
            reqs = self._requests.get(user_id, [])
            reqs = [t for t in reqs if t > now - self.window]
            if len(reqs) >= self.max:
                self._requests[user_id] = reqs
                return False
            reqs.append(now)
            self._requests[user_id] = reqs
            return True


class TelegramNotifier:
    def __init__(self, token: str = "", chat_id: str = ""):
        self.token = token or os.environ.get("TELEGRAM_BOT_TOKEN", "")
        self.chat_id = chat_id or os.environ.get("TELEGRAM_CHAT_ID", "")
        self.base = f"https://api.telegram.org/bot{self.token}"

    def enabled(self) -> bool:
        return bool(self.token and self.chat_id and HAS_REQUESTS)

    def send(self, text: str, parse_mode: str = "Markdown") -> bool:
        if not self.enabled():
            return False
        try:
            resp = requests.post(f"{self.base}/sendMessage", json={
                "chat_id": self.chat_id, "text": text[:4000],
                "parse_mode": parse_mode, "disable_web_page_preview": True,
            }, timeout=10)
            return resp.status_code == 200
        except Exception:
            return False

    def send_report(self, contract_name: str, summary: str, findings_count: int,
                    report_link: str = "") -> bool:
        msg = (
            f"🔍 *Audit Complete*\n"
            f"Contract: `{contract_name}`\n"
            f"Findings: {findings_count}\n"
            f"Summary: {summary[:200]}"
        )
        if report_link:
            msg += f"\n[Full Report]({report_link})"
        return self.send(msg)


class TelegramBot:
    def __init__(self, token: str = ""):
        self.token = token or os.environ.get("TELEGRAM_BOT_TOKEN", "")
        self.base = f"https://api.telegram.org/bot{self.token}"
        self._running = False
        self._offset = 0
        self._thread: threading.Thread = None
        self._monitor_thread: threading.Thread = None
        self._pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)

        self._processing: set = set()
        self._processing_lock = threading.Lock()
        self._rate_limiter = RateLimiter(max_requests=5, window=60)

    # ── Typing indicator ────────────────────────────────────────
    def _send_action(self, chat_id: int, action: str = "typing"):
        try:
            requests.post(f"{self.base}/sendChatAction", json={
                "chat_id": chat_id, "action": action,
            }, timeout=3)
        except Exception:
            pass

    # ── Inline keyboards ────────────────────────────────────────
    def _main_keyboard(self):
        return {
            "inline_keyboard": [
                [{"text": "🔍 Code Audit", "callback_data": "audit_help"}],
                [{"text": "🔬 Auto-PoC Audit", "callback_data": "poc_help"}],
                [{"text": "⛽ Gas Analysis", "callback_data": "gas_help"}],
                [{"text": "📊 Status", "callback_data": "status"}],
                [{"text": "📄 PDF Report", "callback_data": "pdf_help"}],
                [{"text": "🌐 Web UI", "url": WEB_UI_URL}],
                [{"text": "📊 Statistics", "callback_data": "stats"}],
                [{"text": "🌍 Report Language", "callback_data": "lang"}],
                [{"text": "❓ Help", "callback_data": "help"}],
            ]
        }



    def _processing_keyboard(self, chat_id: int):
        return {
            "inline_keyboard": [
                [{"text": "⏳ Processing...", "callback_data": "noop"}],
            ]
        }

    # ── Sending ─────────────────────────────────────────────────
    def _send(self, chat_id: int, text: str, keyboard: dict = None, parse_mode: str = ""):
        if not HAS_REQUESTS:
            return
        payload = {
            "chat_id": chat_id, "text": text[:4000],
        }
        if parse_mode:
            payload["parse_mode"] = parse_mode
        if keyboard:
            payload["reply_markup"] = json.dumps(keyboard)
        try:
            requests.post(f"{self.base}/sendMessage", json=payload, timeout=5)
        except Exception:
            pass

    def _send_document(self, chat_id: int, file_path: str, caption: str = ""):
        if not HAS_REQUESTS:
            return
        try:
            with open(file_path, "rb") as f:
                requests.post(f"{self.base}/sendDocument", data={
                    "chat_id": chat_id, "caption": caption[:200],
                }, files={"document": f}, timeout=60)
        except Exception as e:
            logger.warning(f"sendDocument failed: {e}")

    def _edit_message(self, chat_id: int, msg_id: int, text: str, keyboard: dict = None, parse_mode: str = ""):
        payload = {
            "chat_id": chat_id, "message_id": msg_id,
            "text": text[:4000],
        }
        if parse_mode:
            payload["parse_mode"] = parse_mode
        if keyboard:
            payload["reply_markup"] = json.dumps(keyboard)
        try:
            requests.post(f"{self.base}/editMessageText", json=payload, timeout=5)
        except Exception:
            pass

    def _answer_callback(self, cb_id: str, text: str = ""):
        try:
            requests.post(f"{self.base}/answerCallbackQuery", json={
                "callback_query_id": cb_id, "text": text[:200], "show_alert": False,
            }, timeout=3)
        except Exception:
            pass

    # ── Background worker ───────────────────────────────────────
    def _dispatch(self, fn, chat_id: int, *args, **kwargs):
        def _wrapper():
            key = (chat_id, id(fn))
            with self._processing_lock:
                self._processing.add(key)
            self._send_action(chat_id)
            try:
                fn(chat_id, *args, **kwargs)
            except Exception as e:
                logger.warning(f"Background error: {e}")
                try:
                    self._send(chat_id, f"❌ Error: {e}")
                except Exception:
                    pass
            finally:
                with self._processing_lock:
                    self._processing.discard(key)
        self._pool.submit(_wrapper)

    # ── Stats ───────────────────────────────────────────────────
    def _load_stats(self):
        try:
            if os.path.exists(STATS_FILE):
                with open(STATS_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return {"total_audits": 0, "total_gas": 0, "total_pdf": 0, "users": {}, "findings": {}}

    def _save_stats(self, stats: dict):
        try:
            with open(STATS_FILE, "w", encoding="utf-8") as f:
                json.dump(stats, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _track(self, chat_id: int, action: str, findings_count: int = 0):
        stats = self._load_stats()
        if action == "audit":
            stats["total_audits"] += 1
        elif action == "gas":
            stats["total_gas"] += 1
        elif action == "pdf":
            stats["total_pdf"] += 1
        uid = str(chat_id)
        if uid not in stats["users"]:
            stats["users"][uid] = {"audits": 0, "gas": 0, "pdf": 0}
        stats["users"][uid][action] += 1
        self._save_stats(stats)

    # ── Multi-chain explorer ────────────────────────────────────
    def _fetch_chain_code(self, address: str) -> str:
        for chain, info in CHAIN_EXPLORERS.items():
            apikey = os.environ.get(info["key_var"], "")
            if not apikey:
                continue
            try:
                resp = requests.get(info["api"], params={
                    "module": "contract", "action": "getsourcecode",
                    "address": address, "apikey": apikey,
                }, timeout=15)
                data = resp.json()
                if data.get("status") != "1":
                    continue
                src = data["result"][0].get("SourceCode", "")
                if src.startswith("{"):
                    try:
                        meta = json.loads(src)
                        src = "\n\n".join(
                            v.get("content", "") for v in meta.get("sources", {}).values()
                        ) or src
                    except Exception:
                        pass
                if src.strip():
                    return src[:5000]
            except Exception:
                continue
        return ""

    # ── Zip extractor ───────────────────────────────────────────
    MAX_ZIP_FILE_SIZE = 2 * 1024 * 1024

    def _extract_zip(self, file_path: str) -> str:
        combined = []
        try:
            with zipfile.ZipFile(file_path, "r") as z:
                for name in z.namelist():
                    ext = os.path.splitext(name)[1].lower()
                    if ext in SOURCE_EXTS:
                        info = z.getinfo(name)
                        if info.file_size > self.MAX_ZIP_FILE_SIZE:
                            logger.warning(f"Skipping {name} — {info.file_size} bytes exceeds limit")
                            continue
                        try:
                            content = z.read(name).decode("utf-8", errors="replace")[:2000]
                            combined.append(f"// === {name} ===\n{content}")
                        except Exception:
                            pass
            return "\n\n".join(combined)[:5000]
        except Exception:
            return ""

    # ── Message handler ─────────────────────────────────────────
    def _handle_message(self, text: str, chat_id: int, msg_id: int = None):
        if not self._rate_limiter.allow(chat_id):
            self._send(chat_id, "⏳ Please wait a moment before sending another request.")
            return
        text_stripped = text.strip().lower()
        cmd = text_stripped.split()[0] if text_stripped else ""

        if cmd in ("/start", "/help", "help"):
            self._send(chat_id,
                "🤖 *Smart Contract Auditor Bot*\n\n"
                "📝 Send smart contract code for auditing, a GitHub link, or upload a file.\n"
                "Quick commands:\n"
                "`/audit <code>` — Standard Audit\n"
                "`/poc <code>` — Auto-PoC Audit (validates Critical findings)\n"
                "`/gas <code>` — Gas Analysis\n"
                "`/pdf <code>` — PDF Report\n"
                "`/lang` — Change report language\n"
                "`/status` — System Status",
                keyboard=self._main_keyboard(), parse_mode="Markdown")
            return

        if cmd == "/status":
            self._cmd_status(chat_id, msg_id)
            return

        if cmd == "/stats":
            self._dispatch(self._cmd_stats, chat_id)
            return

        if cmd == "/diff":
            parts = text[5:].strip().split("|")
            if len(parts) < 2:
                self._send(chat_id, "Send the two contracts separated by |\n`/diff contract1 code | contract2 code`")
                return
            self._dispatch(self._cmd_diff, chat_id, parts[0].strip(), parts[1].strip())
            return

        if cmd == "/audit":
            code = text[6:].strip()
            if len(code) < 20:
                self._send(chat_id, "Send the code after /audit:\n`/audit pragma solidity ^0.8.0; ...`")
                return
            self._dispatch(self._run_audit, chat_id, code)
            return

        if cmd == "/poc":
            code = text[4:].strip()
            if len(code) < 20:
                self._send(chat_id, "Send the code after /poc:\n`/poc pragma solidity ^0.8.0; ...`")
                return
            self._dispatch(self._run_poc, chat_id, code)
            return

        if cmd == "/gas":
            code = text[4:].strip()
            if len(code) < 20:
                self._send(chat_id, "Send the code after /gas:\n`/gas pragma solidity ...`")
                return
            self._dispatch(self._run_gas, chat_id, code)
            return

        if cmd == "/pdf":
            code = text[4:].strip()
            if len(code) < 20:
                self._send(chat_id, "Send the code after /pdf:\n`/pdf pragma solidity ...`")
                return
            self._dispatch(self._run_pdf, chat_id, code)
            return

        m = GITHUB_RE.search(text)
        if m:
            self._dispatch(self._handle_github, chat_id, m.group(0))
            return

        addr = ADDRESS_RE.search(text)
        if addr and len(text) < 50:
            self._dispatch(self._handle_address, chat_id, addr.group(0))
            return

        if len(text) > 30:
            self._dispatch(self._run_audit, chat_id, text)
        else:
            self._send(chat_id, "Send a longer code, or use /help", keyboard=self._main_keyboard())

    def _handle_callback(self, cb):
        cb_id = cb["id"]
        data = cb.get("data", "")
        chat_id = cb["message"]["chat"]["id"]
        msg_id = cb["message"]["message_id"]

        if data == "audit_help":
            self._answer_callback(cb_id, "Send the contract code")
            self._edit_message(chat_id, msg_id,
                "🔍 Send the code directly, or upload a .sol/.vy/.move/.clsp file\nOr use /audit <code>")
        elif data == "gas_help":
            self._answer_callback(cb_id, "Gas Analysis")
            self._edit_message(chat_id, msg_id, "⛽ Send the code or use /gas <code>")
        elif data == "pdf_help":
            self._answer_callback(cb_id, "PDF Report")
            self._edit_message(chat_id, msg_id, "📄 Send the code or use /pdf <code>")
        elif data == "status":
            self._answer_callback(cb_id, "Checking status")
            self._cmd_status(chat_id, msg_id)
        elif data == "back":
            self._answer_callback(cb_id, "Back")
            self._edit_message(chat_id, msg_id, "Main menu:", keyboard=self._main_keyboard())
        elif data == "lang":
            self._answer_callback(cb_id, "Language selection disabled")
            self._edit_message(chat_id, msg_id, "Only English is supported", keyboard=self._main_keyboard())
        elif data == "stats":
            self._answer_callback(cb_id, "Loading statistics")
            self._dispatch(self._cmd_stats, chat_id)
        elif data == "poc_help":
            self._answer_callback(cb_id, "Auto-PoC Audit")
            self._send(chat_id,
                "🔬 *Auto-PoC Audit:*\n\n"
                "Analyzes code + validates Critical findings with Foundry test generation.\n\n"
                "Send code directly, or use:\n/poc <code>\n\n"
                "📎 Or upload a .sol file",
                keyboard=self._main_keyboard())
        elif data == "help":
            self._answer_callback(cb_id, "Help menu")
                self._send(chat_id,
                    "🤖 *Commands:*\n\n"
                    "`/audit <code>` — Code Audit\n"
                    "`/poc <code>` — Auto-PoC Audit\n"
                    "`/gas <code>` — Gas Analysis\n"
                    "`/pdf <code>` — PDF Report\n"
                    "`/lang` — Change Language\n"
                    "`/status` — System Status\n\n"
                    "📎 Send a GitHub link\n"
                    "📎 Upload a smart contract file",
                    keyboard=self._main_keyboard(), parse_mode="Markdown")
        else:
            self._answer_callback(cb_id)

    def _handle_document(self, doc, chat_id: int):
        if not self._rate_limiter.allow(chat_id):
            self._send(chat_id, "⏳ Please wait a moment before sending another request.")
            return
        file_id = doc.get("file_id", "")
        file_name = doc.get("file_name", "contract.sol")
        ext = os.path.splitext(file_name)[1].lower()
        if not file_id:
            return
        try:
            resp = requests.get(f"{self.base}/getFile?file_id={file_id}", timeout=10)
            if resp.status_code != 200:
                return
            file_path = resp.json().get("result", {}).get("file_path", "")
            if not file_path:
                return
            dl = requests.get(f"https://api.telegram.org/file/bot{self.token}/{file_path}", timeout=30)
            if dl.status_code != 200:
                return
            tmp = tempfile.NamedTemporaryFile(suffix=ext, delete=False)
            tmp.write(dl.content)
            tmp.close()
            if ext == ".zip":
                code = self._extract_zip(tmp.name)
                if not code:
                    self._send(chat_id, "❌ No smart contract files found in the zip")
                    os.unlink(tmp.name)
                    return
                self._send(chat_id, f"📦 Extracted {code.count('// ===')} files from `{file_name}`\n🔄 Analyzing...")
            else:
                code = dl.text[:5000]
                self._send(chat_id, f"📄 Received `{file_name}`\n🔄 Analyzing...")
            os.unlink(tmp.name)
            self._dispatch(self._run_audit, chat_id, code)
        except Exception as e:
            logger.warning(f"File download failed: {e}")

    def _handle_github(self, chat_id: int, url: str):
        self._send(chat_id, f"🔄 Downloading `{url}`...")
        try:
            from github_loader import extract_repo_info, get_all_sol_files
            owner, repo = extract_repo_info(url)
            if not owner or not repo:
                self._send(chat_id, "❌ Invalid link")
                return
            files = get_all_sol_files(owner, repo)
            if not files:
                self._send(chat_id, "❌ No Solidity files found")
                return
            all_code = "\n\n".join(f["code"][:2000] for f in files[:5])[:3000]
            self._send(chat_id, f"📦 {len(files)} files\n🔄 Analyzing...")
            self._dispatch(self._run_audit, chat_id, all_code)
        except Exception as e:
            self._send(chat_id, f"❌ {e}")

    # ── Commands ────────────────────────────────────────────────
    def _cmd_status(self, chat_id: int, msg_id: int = None):
        openrouter_key = bool(os.environ.get("OPENROUTER_API_KEY"))
        with self._processing_lock:
            qsize = len(self._processing)
        status = (
            f"*🤖 System Status*\n\n"
            f"✅ Bot active\n"
            f"🔑 OpenRouter: {'✅' if openrouter_key else '❌'}\n"
            f"📊 Processing: {qsize}\n"
            f"🌐 [Web UI]({WEB_UI_URL})"
        )
        if msg_id:
            self._edit_message(chat_id, msg_id, status, keyboard=self._main_keyboard(), parse_mode="Markdown")
        else:
            self._send(chat_id, status, keyboard=self._main_keyboard(), parse_mode="Markdown")

    def _cmd_stats(self, chat_id: int, msg_id: int = None):
        self._send_action(chat_id)
        stats = self._load_stats()
        top_findings = sorted(stats.get("findings", {}).items(), key=lambda x: -x[1])[:5]
        top_str = "\n".join(f"  • {k}: {v}" for k, v in top_findings) if top_findings else "  (none)"
        unique_users = len(stats.get("users", {}))
        text = (
            f"*📊 Bot Statistics*\n\n"
            f"🔍 Total Audits: {stats['total_audits']}\n"
            f"⛽ Gas Analyses: {stats['total_gas']}\n"
            f"📄 PDF Reports: {stats['total_pdf']}\n"
            f"👥 Unique Users: {unique_users}\n\n"
            f"*Top Findings:*\n{top_str}"
        )
        if msg_id:
            self._edit_message(chat_id, msg_id, text, keyboard=self._main_keyboard(), parse_mode="Markdown")
        else:
            self._send(chat_id, text, keyboard=self._main_keyboard(), parse_mode="Markdown")

    def _cmd_diff(self, chat_id: int, code1: str, code2: str):
        self._send(chat_id, "🔄 Comparing...")
        self._send_action(chat_id)
        lines1 = code1.splitlines(keepends=True)
        lines2 = code2.splitlines(keepends=True)
        diff = list(unified_diff(lines1, lines2, fromfile="contract1", tofile="contract2", n=3))
        if not diff:
            self._send(chat_id, "✅ Both contracts are identical")
            return
        diff_text = "".join(diff)[:3500]
        self._send(chat_id, f"*📋 Diff Result:*\n```diff\n{diff_text}\n```", parse_mode="Markdown")

    def _handle_address(self, chat_id: int, address: str):
        self._send(chat_id, f"🔄 Fetching code from `{address}`...")
        self._send_action(chat_id)
        code = self._fetch_chain_code(address)
        if not code:
            chains = ", ".join(c.replace("scan","") for c in CHAIN_EXPLORERS)
            self._send(chat_id, f"❌ Could not fetch the code. Make sure:\n1. The address is correct\n2. The API key is set in the environment for any of: {chains}")
            return
        self._send(chat_id, f"✅ Code fetched ({len(code)} chars)\n🔄 Analyzing...")
        self._run_audit(chat_id, code)

    def _run_audit(self, chat_id: int, code: str):
        try:
            from agents import analyze_code
        except Exception as e:
            self._send(chat_id, f"❌ Failed to load analysis engine: {e}")
            return
        dots = ["🔄 Auditing", "🔄 Auditing.", "🔄 Auditing..", "🔄 Auditing..."]
        msg_id = None
        import itertools
        spinner = itertools.cycle(dots)
        stop = threading.Event()
        def progress():
            while not stop.is_set():
                t = next(spinner)
                self._send_action(chat_id)
                stop.wait(4)
        p = threading.Thread(target=progress, daemon=True)
        p.start()
        try:
            result = analyze_code(code[:3000])
            self._send(chat_id, f"*🔍 Audit Result:*\n\n{result[:3500]}")
            self._track(chat_id, "audit")
        except Exception as e:
            logger.exception("Audit failed")
            self._send(chat_id, f"❌ Audit failed: {e}")
        finally:
            stop.set()

    def _run_poc(self, chat_id: int, code: str):
        from orchestrator import dispatch_analysis
        dots = ["🔬 Auto-PoC Audit", "🔬 Auto-PoC Audit.", "🔬 Auto-PoC Audit..", "🔬 Auto-PoC Audit..."]
        stop = threading.Event()
        spinner = itertools.cycle(dots)
        def progress():
            while not stop.is_set():
                self._send_action(chat_id)
                stop.wait(4)
        p = threading.Thread(target=progress, daemon=True)
        p.start()
        try:
            result = dispatch_analysis(code[:4000], analysis_type="autopoc")
            self._send(chat_id, f"*🔬 Auto-PoC Audit Result:*\n\n{result[:3500]}")
            self._track(chat_id, "autopoc")
        finally:
            stop.set()

    def _run_gas(self, chat_id: int, code: str):
        from gas_analysis import analyze_gas
        dots = ["⛽ Gas Analysis", "⛽ Gas Analysis.", "⛽ Gas Analysis..", "⛽ Gas Analysis..."]
        stop = threading.Event()
        spinner = itertools.cycle(dots)
        def progress():
            while not stop.is_set():
                self._send_action(chat_id)
                stop.wait(4)
        p = threading.Thread(target=progress, daemon=True)
        p.start()
        try:
            self._send_action(chat_id)
            result = analyze_gas(code[:3000])
            self._send(chat_id, f"*⛽ Gas Analysis:*\n\n{result[:3500]}")
            self._track(chat_id, "gas")
        finally:
            stop.set()

    # ── Polling ─────────────────────────────────────────────────
    def _poll(self):
        while self._running:
            try:
                resp = requests.get(f"{self.base}/getUpdates", params={
                    "offset": self._offset, "timeout": 30,
                }, timeout=35)
                if resp.status_code != 200:
                    continue
                for update in resp.json().get("result", []):
                    self._offset = update["update_id"] + 1
                    cb = update.get("callback_query")
                    if cb:
                        self._handle_callback(cb)
                        continue
                    msg = update.get("message", {})
                    chat_id = msg.get("chat", {}).get("id")
                    text = msg.get("text", "")
                    doc = msg.get("document")
                    if doc and chat_id:
                        self._handle_document(doc, chat_id)
                    elif text and chat_id:
                        self._handle_message(text, chat_id, msg.get("message_id"))
            except Exception:
                time.sleep(5)

    # ── Lifecycle ───────────────────────────────────────────────
    def start(self, start_monitor: bool = False):
        if self._thread is not None and self._thread.is_alive():
            logger.warning("Telegram bot already running")
            return
        if not self.token or not HAS_REQUESTS:
            logger.warning("Telegram bot not configured")
            return
        self._running = True
        self._notifiers = []
        self._thread = threading.Thread(target=self._poll, daemon=True)
        self._thread.start()
        logger.info("Telegram bot started")

    def stop(self):
        self._running = False
        self._pool.shutdown(wait=False)


_NOTIFIER = TelegramNotifier()
_BOT = TelegramBot()


def get_notifier() -> TelegramNotifier:
    return _NOTIFIER


def get_bot() -> TelegramBot:
    return _BOT
