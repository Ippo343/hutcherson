#!/usr/bin/env python3
# -*- coding: utf8 -*-

import argparse
import json
import logging
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


def is_pr_event(data):
    return 'pull_request' in data


def is_push_event(data):
    return 'ref' in data and 'before' in data and 'after' in data


class RequestHandler(BaseHTTPRequestHandler):
    options = None

    def _set_response(self, response_code=200, message=None):
        self.send_response(response_code)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        if message:
            self.wfile.write(message)

    def do_GET(self):
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        self._set_response(
            response_code=200,
            message="GET request for {}\n".format(self.path).encode('utf-8')
        )

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])  # <--- Gets the size of data
        logging.info("POST request,\nPath: %s\nHeaders:\n%s\n\n",
                     str(self.path), str(self.headers))

        secret = self.headers.get(self.options.security_header)
        if not secret or secret != self.options.secret:
            self._set_response(
                response_code=403,
                message="403: forbidden\n".encode('utf-8')
            )
            return

        post_data = self.rfile.read(content_length).decode('utf-8')  # <--- Gets the data itself
        post_data = json.loads(post_data)

        if is_pr_event(post_data):
            self.handle_pull_request(post_data)
        elif is_push_event(post_data):
            self.handle_push(post_data)
        else:
            self._set_response(
                response_code=406,
                message="Not recognized\n".encode('utf-8'))

    def handle_pull_request(self, post_data):

        pr_data = post_data['pull_request']
        logging.info(
            "Event for PR #{} from {} to {}".format(
                post_data['number'],
                pr_data['head']['label'],
                pr_data['base']['label'],
            )
        )

    def handle_push(self, post_data):

        logging.info(
            "Push event for {} ({} -> {})".format(
                post_data['ref'],
                post_data['before'],
                post_data['after'],
            )
        )


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
