#!/usr/bin/env python3
"""Mock Jiangsu ESurfing portal for testing tylogin-native's HTTP layer.

Serves the detect -> check -> BAS -> index.cgi redirect chain, a ticket.cgi
that validates the posted headers (Algo-ID / Client-ID / CDC-Checksum), and
an auth.cgi that responds with a fake error so no real credentials are needed.

Run: python3 tools/mock_portal.py [port]
Test: TY_PORTAL_BASE=http://127.0.0.1:8899 ./build/tylogin -u test -p test -d
"""
import base64
import hashlib
import http.server
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
seen = {}


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("[mock] %s\n" % (fmt % args))

    def _send(self, code, body=b"", headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        host = f"127.0.0.1:{PORT}"
        if self.path.startswith("/detect.html"):
            self._send(200, b"<html>ok</html>")
        elif self.path.startswith("/check"):
            # real chain: check ->302-> path-less BAS url (http://IP?query)
            self._send(302, b"", {"Location": f"http://{host}?ip=1.2.3.4"})
        elif self.path == "/" or self.path.startswith("/?"):
            # BAS ->302-> preportal index.cgi (path-ful)
            qs = "wlanuserip=10.20.30.40&mscgip=1.1.1.1&wlanusermac=AA%3ABB%3ACC&userlocation=jsnj"
            self._send(302, b"", {"Location": f"http://{host}/index.cgi?tag=TESTTAG&{qs}"})
        elif self.path.startswith("/index.cgi"):
            xml = f"""<html><!-- <config>
<ticket-url><![CDATA[http://{host}/ticket.cgi?tag=TESTTAG]]></ticket-url>
<auth-url><![CDATA[http://{host}/auth.cgi]]></auth-url>
<account><modify><type>del-domain</type><value>@f-young.cn</value></modify></account>
<auth><type>cdc-http-pap</type></auth>
</config> --></html>"""
            self._send(200, xml.encode(), {"Content-Type": "text/html"})
        else:
            self._send(404, b"nope")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n)
        algo = self.headers.get("Algo-ID", "")
        cid = self.headers.get("Client-ID", "")
        cks = self.headers.get("CDC-Checksum", "")
        calc = hashlib.md5(body).hexdigest()
        ok = "OK" if calc == cks else f"MISMATCH(calc={calc})"
        seen["last"] = (self.path, algo[:8], cid[:8], cks[:8], ok)
        sys.stderr.write(f"[mock] POST {self.path} len={n} Algo-ID={algo[:12]}… "
                         f"Client-ID={cid[:12]}… CDC-Checksum={cks} md5={calc} -> {ok}\n")
        if self.path.startswith("/ticket.cgi"):
            # not a real module: the client must fail the load gracefully
            self._send(200, b"001@" + b"0" * 64 + b"$" + b"0" * 36 + b"]" + b"XX" * 32,
                       {"Error-Code": "200"})
        elif self.path.startswith("/auth.cgi"):
            self._send(200, b"deadbeef" * 4, {"Error-Code": "15", "Sub-Error": "0"})
        else:
            self._send(404, b"nope")


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
