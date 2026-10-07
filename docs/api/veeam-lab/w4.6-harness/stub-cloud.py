"""W4.6 (#49): a stub Cloud for the outbox's Done-when run. Not the Cloud: W5.1 builds /v1/results.

    python stub-cloud.py --cert <pem> --key <pem> [--port 8443] [--slow]

Listens on https://localhost:<port> with the certificate given (self-signed, made for the run and
named in a copy of the lab config as cloud_ca_file). Answers 202 to POST /v1/results once it has
read the whole body, 404 to anything else. --slow reads the first 1024 bytes of a body and then
sleeps 20 s, so the stub can be killed in the middle of an upload. Prints one line per request and
one per multipart part: its name, file name, size and SHA-256. Never a body.
"""
import argparse, hashlib, http.server, re, ssl, sys, time


def parts_of(content_type: str, body: bytes):
    boundary = re.search(r'boundary="?([^";]+)"?', content_type or "")
    if not boundary:
        return
    for chunk in body.split(b"--" + boundary.group(1).encode())[1:-1]:
        head, _, data = chunk.partition(b"\r\n\r\n")
        disposition = head.decode("utf-8", "replace")
        name = re.search(r'\bname="([^"]*)"', disposition)
        filename = re.search(r'filename="([^"]*)"', disposition)
        yield (name.group(1) if name else "?", filename.group(1) if filename else "-", data[:-2])


class Handler(http.server.BaseHTTPRequestHandler):
    slow = False

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(min(length, 1024))
        if self.slow:
            print(f"POST {self.path}: read {len(body)} of {length} bytes, sleeping 20 s", flush=True)
            time.sleep(20)
        body += self.rfile.read(length - len(body))
        accepted = self.path == "/v1/results"
        print(f"POST {self.path}: {length} bytes, Authorization {'present' if self.headers.get('Authorization') else 'absent'}"
              f" -> {202 if accepted else 404}", flush=True)
        for name, filename, data in parts_of(self.headers.get("Content-Type"), body):
            print(f"  part {name}  file {filename}  {len(data)} bytes  sha256 {hashlib.sha256(data).hexdigest()}", flush=True)
        self.send_response(202 if accepted else 404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--slow", action="store_true")
    args = parser.parse_args()
    Handler.slow = args.slow
    server = http.server.HTTPServer(("127.0.0.1", args.port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"stub Cloud on https://localhost:{args.port}{' (slow)' if args.slow else ''}", flush=True)
    sys.stdout.flush()
    server.serve_forever()
