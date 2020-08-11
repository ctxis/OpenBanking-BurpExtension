#!/usr/bin/python3

from http.server import BaseHTTPRequestHandler, HTTPServer
import random

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        paramIndex = self.path.find("?")
        urlPath = self.path
        if paramIndex != -1:
            urlPath = self.path[:paramIndex]

        if 'pisp/domestic-payment-consents/1' in urlPath:
            # static example for a path without message signing requirement
            message = "Consent details - MessageSigning - false"
            self.protocol_version = "HTTP/1.1"
            self.send_response(200)
            self.send_header("Content-Length", len(message))
            self.end_headers()
            self.wfile.write(bytes(message, "utf8"))
        if 'callback' in urlPath:
            # static example for the TPP redirect URL
            message1 = "Open Banking Redirect URL"
            self.protocol_version = "HTTP/1.1"
            self.send_response(200)
            self.send_header("Content-Length", len(message1))
            self.end_headers()
            self.wfile.write(bytes(message1, "utf8"))
        elif 'ob/login' in urlPath:
            # example OB login for consent authorisation
            messageObLogin = "<!DOCTYPE html><html><body><p>This page represents a login page<p><p><a href='http://127.0.0.1/redirect'>Login and authorise</a></p></body></html>"
            self.protocol_version = "HTTP/1.1"
            self.send_response(200)
            self.send_header("Content-Length", len(messageObLogin))
            self.end_headers()
            self.wfile.write(bytes(messageObLogin, "utf8"))
        elif 'redirect' in urlPath:
            # this is a stub for the 302 redirect the ASPSP would setup to the
            # TPP redirect URL (this is what the burp extension is listening for)
            self.protocol_version = "HTTP/1.1"
            self.send_response(302)
            self.send_header("Location", "http://tpp.ctx/callback#code=" + ''.join(random.choice('0123456789ABCDEF') for i in range(16)) + "&id_token=jws")
            self.end_headers()
        else:
            # otherwise return 404
            self.protocol_version = "HTTP/1.1"
            self.send_response(404)
            self.end_headers()
        return

    def do_POST(self):
        paramIndex = self.path.find("?")
        urlPath = self.path
        if paramIndex != -1:
            urlPath = self.path[:paramIndex]

        if 'pisp/domestic-payment-consents' in urlPath:
            # static example for a path with message signing requirement
            message = '{"Data": {"ConsentId": "1234567890", "Status": "AwaitingAuthorisation", ...}}'
            self.protocol_version = "HTTP/1.1"
            self.send_response(200)
            self.send_header("Content-Length", len(message))
            self.end_headers()
            self.wfile.write(bytes(message, "utf8"))
        elif 'token.oauth2' in urlPath:
            # stubbed example for an ASPSP OAuth endpoint
            message = '{"access_token":"' + ''.join(random.choice('0123456789ABCDEF') for i in range(16)) + '","refresh_token":"' + ''.join(random.choice('0123456789ABCDEF') for i in range(16)) + '","token_type":"Bearer","expires_in":299}'
            self.protocol_version = "HTTP/1.1"
            self.send_response(200)
            self.send_header("Content-Length", len(message))
            self.end_headers()
            self.wfile.write(bytes(message, "utf8"))
        else:
            # otherwise return 404
            self.protocol_version = "HTTP/1.1"
            self.send_response(404)
            self.end_headers()
        return

def run():
    server = ('', 80)
    httpd = HTTPServer(server, RequestHandler)
    httpd.serve_forever()
run()
