#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import argparse

import sys


class RequestHandler(BaseHTTPRequestHandler):
    options = None

    def _set_response(self, response_code=200):
        self.send_response(response_code)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        self._set_response()
        self.wfile.write("GET request for {}\n".format(self.path).encode('utf-8'))

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])  # <--- Gets the size of data
        post_data = self.rfile.read(content_length).decode('utf-8')  # <--- Gets the data itself
        logging.info("POST request,\nPath: %s\nHeaders:\n%s\n\n",
                     str(self.path), str(self.headers))

        secret = self.headers.get(self.options.security_header)
        if not secret or secret != self.options.secret:
            self._set_response(403)
            self.wfile.write("403: forbidden\n".encode('utf-8'))
        else:
            self._set_response()
            self.wfile.write("Your data is being processed (meh)\n".encode('utf-8'))


def run(options):
    server_address = ('', options.port)
    RequestHandler.options = options
    httpd = HTTPServer(server_address, RequestHandler)

    logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

    httpd.server_close()
    logging.info('Stopping httpd...\n')


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, default=48464)
    parser.add_argument('--security-header', type=str, default='X-Hub-Signature')
    parser.add_argument('--secret', type=str, required=True)
    args = parser.parse_args(sys.argv[1:])

    run(args)
