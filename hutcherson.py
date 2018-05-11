#!/usr/bin/env python3
# -*- coding: utf8 -*-

import argparse
import configparser
import hmac
import json
import logging
from http import HTTPStatus

import requests
import shelve
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

from requests.auth import HTTPBasicAuth


class Hutcherson(BaseHTTPRequestHandler):
    """
    Request handler that reacts to Github's push and PR hooks.
    Keeps a list of the open PRs and posts a comment when their target branch is updated.
    """

    security_header = None
    security_secret = None
    storage_path = None
    comment_auth = None
    pr_comment = None

    # region Boring stuff

    def _set_response(self, response_code):
        """
        Sets the response code to send to the caller, with an optional message
        :type response_code: HTTPStatus
        """
        self.send_response(response_code.value)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(response_code.phrase.encode("utf8"))

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

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        auth = self.headers.get(self.security_header)
        if not self.validate_token(auth, post_data):
            logging.warning("Received a POST request with an invalid token "
                            "from {}".format(self.client_address))

            self._set_response(HTTPStatus.FORBIDDEN)
            return

        # endregion

        post_data = post_data.decode('utf-8')
        logging.info("POST request from {}.\nHeaders:\n{}".format(self.path, self.headers))

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

        with shelve.open(self.storage_path, writeback=True) as store:

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

        with shelve.open(self.storage_path) as store:
            affected_prs = [pr for pr in store["pulls"].values() if pr.target == branch]

        for pr in affected_prs:
            try:
                logging.debug("Updating {}".format(pr))
                self.handle_affected_pr(pr)
            except Exception as e:
                logging.exception("Could not update {}".format(pr.id), e)
                continue

    def handle_affected_pr(self, pr):
        """
        Posts a comment under a single PR that is affected by a push
        """

        payload = {"body": self.pr_comment}

        # Yep, for some reason the API endpoint to post a comment is not under "pull". Go figure.
        url = pr.api_url.replace("/pulls/", "/issues/") + "/comments"
        logging.debug("Posting comment to {}".format(url))

        req = requests.post(url, data=json.dumps(payload), auth=Hutcherson.comment_auth)
        logging.debug("Request completed with status {}".format(req))

    def validate_token(self, auth, post_data):
        hasher = hmac.new(self.security_secret, msg=post_data, digestmod="sha1")
        digest = "sha1=" + hasher.hexdigest()
        return hmac.compare_digest(digest, auth)


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


def run(config):
    address = config.get("server", "address")
    port = int(config.get("server", "port"))

    Hutcherson.security_header = config.get("security", "header")
    Hutcherson.security_secret = config.get("security", "token")
    Hutcherson.storage_path = config.get("storage", "path")

    Hutcherson.pr_comment = config.get("comment", "body")
    Hutcherson.comment_auth = HTTPBasicAuth(
        config.get("comment", "user"),
        config.get("comment", "token")
    )

    Hutcherson.security_secret = Hutcherson.security_secret.encode("utf8")

    httpd = HTTPServer((address, port), Hutcherson)

    logging.info('Starting server on {}'.format(httpd.server_address))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logging.warning("Shutdown requested")
        pass

    httpd.server_close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s|%(levelname)8s|%(message)s")

    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=str)
    args = parser.parse_args(sys.argv[1:])

    config_file = configparser.ConfigParser()
    config_file.read(args.config)

    # Create a default, empty shelve for the first run
    with shelve.open(config_file.get("storage", "path"), writeback=True) as store:
        store.setdefault("pulls", {})

    run(config_file)
    logging.info("Bye!")
