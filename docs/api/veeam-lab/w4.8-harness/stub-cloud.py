"""W4.8 (#51): a stub Cloud for the scheduler loop's Done-when run. Not the Cloud: W5.1 and C5.x build it.

    python stub-cloud.py --cert <pem> --key <pem> [--port 8444]

Listens on https://localhost:<port> with the certificate given (self-signed, made for the run and
named in a copy of the lab config as cloud_ca_file). Answers 202 to POST /v1/results once it has
read the whole body, 204 to POST /v1/heartbeat, 404 to anything else, each with the contract's
`X-RestoreProof-API: 1` (since W5.1 the Worker takes a 2xx without it as no Cloud's, and sends
nothing without the vault's cloud_api_token: Start-W48Stub puts a token of the run's own there). Prints one line per request
with its UTC time; for a result one line per multipart part (its name, file name, size and
SHA-256, never a body), for a heartbeat the JSON body as it came (it holds no secret: a version,
two numbers, a fixed word and a time).
"""
import argparse, datetime, hashlib, http.server, re, ssl, sys


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        authorization = "present" if self.headers.get("Authorization") else "absent"
        if self.path == "/v1/heartbeat":
            status = 204
            print(f"{now()} POST {self.path}: {length} bytes, Content-Type {self.headers.get('Content-Type')}, "
                  f"Authorization {authorization} -> {status}  {body.decode('utf-8', 'replace')}", flush=True)
        else:
            status = 202 if self.path == "/v1/results" else 404
            print(f"{now()} POST {self.path}: {length} bytes, Authorization {authorization} -> {status}", flush=True)
            for name, filename, data in parts_of(self.headers.get("Content-Type"), body):
                print(f"  part {name}  file {filename}  {len(data)} bytes  sha256 {hashlib.sha256(data).hexdigest()}", flush=True)
        self.send_response(status)
        self.send_header("X-RestoreProof-API", "1")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--port", type=int, default=8444)
    args = parser.parse_args()
    server = http.server.HTTPServer(("127.0.0.1", args.port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"{now()} stub Cloud on https://localhost:{args.port}", flush=True)
    sys.stdout.flush()
    server.serve_forever()
