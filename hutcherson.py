#!/usr/bin/env python3
# -*- coding: utf8 -*-

import argparse
import json
import logging
from http import HTTPStatus

import requests
import shelve
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Hutcherson(BaseHTTPRequestHandler):
    """
    Request handler that reacts to Github's push and PR hooks.
    Keeps a list of the open PRs and posts a comment when their target branch is updated.
    """

    options = None

    # region Boring stuff

    def _set_response(self, response_code):
        """
        Sets the response code to send to the caller, with an optional message
        :type response_code: HTTPStatus
        """
        self.send_response(response_code.value)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(response_code.phrase)

    def do_GET(self):
        # This server is not supposed to receive a GET, ever.
        # If it happens it's probably a spambot of some sort, log an error for fail2ban
        logging.warning("Received GET request for {} from {}".format(self.path, self.client_address))
        self._set_response(HTTPStatus.FORBIDDEN)

    # endregion

    def do_POST(self):

        # region secret token validation
        # Github sends a secret token which is set when the hook is installed,
        # if the token does not match ignore the request (again, spambots)

        secret = self.headers.get(self.options.security_header)
        if not secret or secret != self.options.secret:
            logging.warning("Received a POST request with an invalid token "
                            "from {}".format(self.client_address))

            self._set_response(HTTPStatus.FORBIDDEN)
            return

        # endregion

        logging.info("POST request from {}.\nHeaders:\n{}".format(self.path, self.headers))

        content_length = int(self.headers['Content-Length'])  # <--- Gets the size of data
        post_data = self.rfile.read(content_length).decode('utf-8')  # <--- Gets the data itself

        try:
            post_data = json.loads(post_data)
        except Exception as e:
            logging.exception("Could not parse the request data", e)
            self._set_response(HTTPStatus.BAD_REQUEST)
            return

        if is_pr_event(post_data):
            self.handle_pull_request(post_data)
            self._set_response(HTTPStatus.OK)

        elif is_push_event(post_data):
            self.handle_push(post_data)
            self._set_response(HTTPStatus.OK)

        elif is_ping(post_data):
            self._set_response(HTTPStatus.OK)

        else:
            self._set_response(HTTPStatus.BAD_REQUEST)

    def handle_pull_request(self, post_data):
        """
        Handles a pull request event, either saving a new PR or by deleting a closed one.
        """

        action = post_data['action']
        pr = PullRequest(post_data)
        logging.info("{} is {}".format(pr, action))

        with shelve.open(self.options.store, writeback=True) as store:

            if action in ('opened', 'reopened'):
                store["pulls"][pr.id] = pr
                logging.debug("{} stored".format(pr))

            elif action == 'closed':
                try:
                    del store["pulls"][pr.id]
                    logging.debug("PR {} deleted".format(pr.id))
                except KeyError:
                    pass

    def handle_push(self, post_data):
        """
        Finds all the PRs that depend on the pushed branch and posts a comment.
        """

        branch = get_pushed_branch(post_data)
        logging.info("{} was pushed".format(branch))

        with shelve.open(self.options.store) as store:
            affected_prs = [pr for pr in store["pulls"].values() if pr.target == branch]

        for pr in affected_prs:
            try:
                logging.debug("Updating {}")
                self.handle_affected_pr(pr)
            except Exception as e:
                logging.exception("Could not update {}".format(pr.id), e)
                continue

    def handle_affected_pr(self, pr):
        """
        Posts a comment under a single PR that is affected by a push
        """

        payload = {"body": "The target branch for this PR was pushed"}

        # Yep, for some reason the API endpoint to post a comment is not under "pull". Go figure.
        url = pr.api_url.replace("/pulls/", "/issues/") + "/comments"
        logging.debug("Posting comment to {}".format(payload, url))

        req = requests.post(url, data=json.dumps(payload))
        logging.debug("Request completed with status {}".format(req))


# region Helpers

def is_pr_event(data):
    return 'pull_request' in data


def is_push_event(data):
    return all(k in data for k in ('ref', 'before', 'after'))


def get_pushed_branch(post_data):
    ref = post_data['ref'].split('/')[-1]
    return post_data['repository']['full_name'] + '/' + ref


def is_ping(post_data):
    return "hook" in post_data and "type" in post_data["hook"] and "events" in post_data["hook"]


def get_full_branch(repo_data):
    return repo_data['repo']['full_name'] + '/' + repo_data['ref']


# endregion


class PullRequest:
    def __init__(self, post_data):
        pr_data = post_data['pull_request']
        self.id = pr_data['id']
        self.api_url = pr_data['url']
        self.origin = get_full_branch(pr_data['head'])
        self.target = get_full_branch(pr_data['base'])

    def __str__(self):
        return "PR {} from {} to {}".format(self.id, self.origin, self.target)


def run(options):
    server_address = ('', options.port)
    Hutcherson.options = options
    httpd = HTTPServer(server_address, Hutcherson)

    logging.info('Starting server on {}'.format(server_address))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logging.warning("Shutdown requested")
        pass

    httpd.server_close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s|%(levelname)8s|%(message)s")

    # region argparse config

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, default=48464)
    parser.add_argument('--security-header', type=str, default='X-Hub-Signature')
    parser.add_argument('--secret', type=str, required=True)
    parser.add_argument('--store', type=str, default="db")
    args = parser.parse_args(sys.argv[1:])

    # endregion

    # Create a default, empty shelve for the first run
    with shelve.open(args.store, writeback=True) as store:
        store.setdefault("pulls", {})

    run(args)
    logging.info("Bye!")
