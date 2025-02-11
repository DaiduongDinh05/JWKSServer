import http.server
import socketserver
import json
import time
from urllib.parse import urlparse, parse_qs
import jwt
handler = http.server.SimpleHTTPRequestHandler
if __name__ == "__main__":
    PORT = 8080
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        print(f"Serving on port {PORT}...")
        httpd.serve_forever()
name = "hi"