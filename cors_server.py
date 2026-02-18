from http.server import HTTPServer, SimpleHTTPRequestHandler
import sys

class CORSHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET')
        super().end_headers()

HTTPServer(('', int(sys.argv[1]) if len(sys.argv) > 1 else 8877), CORSHandler).serve_forever()
