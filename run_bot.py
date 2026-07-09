import sys, os, threading, time
sys.path.insert(0, os.path.dirname(__file__))
from telegram_bot import get_bot

PORT = int(os.environ.get("PORT", 8080))

def _health_server():
    try:
        from http.server import HTTPServer, BaseHTTPRequestHandler
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")
            def log_message(self, *a):
                pass
        server = HTTPServer(("0.0.0.0", PORT), H)
        server.serve_forever()
    except Exception:
        pass

threading.Thread(target=_health_server, daemon=True).start()

bot = get_bot()
bot.start(start_monitor=True)
print(f"Bot running on port {PORT}... Ctrl+C to stop")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    bot.stop()
