# coding=utf-8

"""
    poodledo.auth_server
    ~~~~~~~~~~~~~~~~~~~~

    The authentication code will be send to this local server.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
import six


class AuthHTTPServer(HTTPServer):
    """Local HTTP server for authentication."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.response_data = dict()


class AuthHTTPRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler to GET authentication code."""

    def do_GET(self):  # pylint: disable=invalid-name
        """Handle GET request."""
        # Send response status code.
        self.send_response(200)
        # Send response headers.
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        for key, value in six.iteritems(parse_qs(self.path[2:])):
            self.server.response_data[key] = value

        message = ("<b>Poodledo</b>: The authentication flow completed." +
                   "You can close this window.")
        self.wfile.write(message.encode('utf-8'))


def handle_request():
    """Run the HTTP server."""
    server_addr = ("localhost", 31415)
    httpd = AuthHTTPServer(server_addr, AuthHTTPRequestHandler)
    httpd.handle_request()
    return httpd.response_data
