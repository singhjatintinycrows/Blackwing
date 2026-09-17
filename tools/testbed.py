"""A deliberately-vulnerable local target for trying Blackwing's web track (authorised: it's
localhost, yours). Reflected XSS, SSTI, and boolean-SQLi-shaped behaviour. NOT for production."""
import http.server, socketserver, urllib.parse, re, sys

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _s(self, b, c=200):
        self.send_response(c); self.send_header("Content-Type","text/html"); self.end_headers()
        self.wfile.write(b.encode())
    def do_GET(self):
        u = urllib.parse.urlparse(self.path); q = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
        if u.path == "/":
            self._s('<html><body><h1>Juice Corner (test target)</h1>'
                    '<a href="/search?q=apple">search</a> | '
                    '<a href="/greet?name=friend">greet</a> | '
                    '<a href="/item?id=1">item</a></body></html>')
        elif u.path == "/search":
            self._s(f'<html><body>You searched for: {q.get("q","")}</body></html>')
        elif u.path == "/greet":
            name = q.get("name","")
            name = re.sub(r'\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}', lambda m:str(int(m.group(1))*int(m.group(2))), name)
            self._s(f'<html><body>Hello, {name}!</body></html>')
        elif u.path == "/item":
            idv = q.get("id","")
            self._s('<html><body>no such item</body></html>' if "'1'='2" in idv
                    else '<html><body>Item #1: Mango Juice, $3.50, in stock</body></html>')
        else:
            self._s('<html><body>404</body></html>',404)

port = int(sys.argv[1]) if len(sys.argv)>1 else 8477
with socketserver.TCPServer(("127.0.0.1",port),H) as s:
    print(f"testbed on http://127.0.0.1:{port}"); s.serve_forever()
