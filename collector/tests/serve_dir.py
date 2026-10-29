"""Serve a directory over HTTP on 127.0.0.1 (random port) for install.ps1 download tests.
Usage: python serve_dir.py <dir> <info-file>; runs until stdin closes."""
import functools
import json
import os
import sys
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


class Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


def main():
    handler = functools.partial(Quiet, directory=sys.argv[1])
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    tmp = sys.argv[2] + ".tmp"
    with open(tmp, "w") as fh:
        json.dump({"url": f"http://127.0.0.1:{httpd.server_address[1]}"}, fh)
    os.replace(tmp, sys.argv[2])
    sys.stdin.read()
    httpd.shutdown()


if __name__ == "__main__":
    main()
