#!/usr/bin/env python3

import argparse
import re
import socket
import ssl
import html
import sys
from html.parser import HTMLParser
import urllib.parse
import xml
import queue
import gzip

DEFAULT_SERVER = "proj5.3700.network"
DEFAULT_PORT = 443
ORIGIN = 'https://www.3700.network'
MAX_BYTES = 65535


class HttpRequestBuilder:
    def __init__(self, method="GET", version="1.0", host="www.3700.network"):
        """
        Initializes an instance of HttpRequestBuilder.

        Args:
        - method (str): The HTTP method, default is "GET".
        - version (str): The HTTP version, default is "1.0".
        - host (str): The host to send the request to, default is "www.3700.network".
        """
        self.version = str(version)
        self.method = str(method)
        self.host = str(host)
        self.headers = {}
        self.body = ''


    def set_method(self, method):
        """
        Sets the HTTP method for the request.

        Args:
        - method (str): The HTTP method to set.
        """
        self.method = str(method)
        return self

    def set_path(self, path):
        """
        Sets the path for the request.

        Args:
        - path (str): The path to set.
        """
        self.path = str(path)
        return self

    def add_header(self, key, value):
        """
        Adds a header to the request.

        Args:
        - key (str): The header key.
        - value (str): The header value.
        """
        try:
            key = str(key)
            value = str(value)
        except Exception as e:
            raise ValueError("Header key and value must be convertible to strings") from e
        self.headers[key] = value
        return self

    def set_body(self, body):
        """
        Sets the body of the request.

        Args:
        - body (str): The body content to set.
        """
        try:
            self.body = str(body)
        except Exception as e:
            raise ValueError("Body must be convertible to a string") from e
        return self

    def build(self):
        """
        Builds the HTTP request.

        Returns:
        - bytes: The encoded HTTP request.
        """
        request = f"{self.method} {self.path} HTTP/{self.version}\r\n"

        if self.headers:
            request += "\r\n".join([f"{key}: {value}" for key, value in self.headers.items()])
            request += "\r\n"

        request += f"Host: {self.host}\r\n"
        request += f"Accept-Encoding: gzip\r\n"
        request += "Connection: keep-alive\r\n"

        if self.body:
            request += f"Content-Length: {len(self.body)}\r\n"
            request += "\r\n"
            request = request.encode("ascii") + self.body.encode("ascii")
        else:
            request += "\r\n"
            request = request.encode("ascii")

        return request


class MyHTMLParser(HTMLParser):
    def __init__(self, queue, flag_callback):
        """
        Initializes an instance of MyHTMLParser.

        Args:
        - queue (Queue): The queue for storing parsed URLs.
        - flag_callback (function): The callback function to call when a flag is found.
        """
        super().__init__()
        self.queue = queue
        self.flags = []
        self.flag_text = None
        self.flag_callback = flag_callback  # Callback function to notify when a flag is found
        self.flag_count = 0
        self.stop_parsing = False

    def handle_starttag(self, tag, attrs):
        """
        Handles start tags in HTML.

        Args:
        - tag (str): The HTML tag.
        - attrs (list): List of (name, value) pairs containing the attributes of the tag.
        """
        if tag == 'a':
            for attr in attrs:
                if attr[0] == 'href':
                    if attr[1] != "/" and attr[1] != "/accounts/logout/":
                        self.queue.put(attr[1])
        if tag == 'h3':
            for attr in attrs:
                if attr[0] == 'class' and attr[1] == 'secret_flag':
                    self.flag_text = ""


    def handle_endtag(self, tag):
        """
        Handles end tags in HTML.

        Args:
        - tag (str): The HTML tag.
        """
        if tag == 'h3' and self.flag_text is not None:
            print(self.flag_text.strip())
            self.flags.append(self.flag_text.strip())
            self.flag_callback()  # Call the callback function
            self.flag_text = None
            if self.flag_count == 5:
                self.stop_parsing = True  # Stop parsing if 5 flags are found


    def handle_data(self, data):
        """
        Handles data within HTML tags.

        Args:
        - data (str): The data within the HTML tag.
        """
        if self.flag_text is not None:
            flag_prefix = "FLAG:"
            start_index = data.find(flag_prefix)
            if start_index != -1:
                self.flag_text += data[start_index + len(flag_prefix):].strip()

    def feed(self, data: str):
        """
        Feeds data to the parser.

        Args:
        - data (str): The data to be parsed.
        """
        super().feed(data)
        return


class Crawler:
    def __init__(self, args):
        """
        Initializes an instance of Crawler.

        Args:
        - args: The command line arguments parsed by argparse.
        """
        self.server = args.server
        self.port = args.port
        self.username = args.username
        self.password = args.password

        self.mysocket = None
        self.queue = queue.Queue(0)
        self.parser = MyHTMLParser(self.queue, self.handle_flag_found)

        self.header: dict = {}
        self.body: str = ''

        self.next_url = ""
        self.session_cookie = ""
        self.csrf_cookie = ""
        self.visited_pages = set()
        self.flags_found = 0  # Track the number of flags found
        self.max_flags = 5  # Maximum number of flags to find
        self.stop_crawling = False  # Flag to indicate whether crawling should stop

    def connect(self):
        """
        Establishes a socket connection.
        """
        if self.port == 80:
            self.mysocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.mysocket.connect((self.server, self.port))
        else:
            context = ssl.create_default_context()
            basic_socket = socket.create_connection((self.server, self.port))
            self.mysocket = context.wrap_socket(basic_socket, server_hostname=self.server)

    def run(self):
        """
        Runs the crawler.
        """
        self.login()
        self.crawl_all_pages()
        
    def exchange(self, request: str):
        """
        Sends and receives data over the socket connection.

        Args:
        - request (str): The HTTP request to be sent.
        """
        try:
            self.mysocket.send(request)
            self.receive()
            self.handle() 
        except ValueError:
            self.connect()
            self.exchange(request)
        
    def receive(self):
        """
        Receives data from the socket connection.
        """
        data = self.mysocket.recv(MAX_BYTES)

        header_match = re.search(br'^(.*?)\r\n\r\n', data, re.DOTALL)
        if header_match:
            header_bytes = header_match.group(0)
        
        header = header_bytes.decode("utf-8")
        # print(header, "\n")
        self.header = self.parse_header(header)
        
        if self.header.get("connection") != 'keep-alive':
            raise ValueError("Connection no longer valid. Reconnect.")

        content_length = int(self.header.get("content-length"))
        received_body = data[len(header_bytes):]

        while len(received_body) < content_length:
            chunk = self.mysocket.recv(MAX_BYTES)
            received_body += chunk

        self.body = gzip.decompress(received_body).decode('utf-8')


    def handle(self):
        """
        Handles the received HTTP response.
        """
        status = self.header.get("status")
        if status == "200":
            pass
        elif status == "302":
            return self.redirect(self.header.get("location"))
        elif status in ("403", "404"):
            pass
        elif status == "503":
            pass

    def redirect(self, url):
        """
        Handles HTTP redirection.

        Args:
        - url (str): The URL to redirect to.
        """
        if self.session_cookie is not None and self.csrf_cookie is not None:
            request = HttpRequestBuilder("GET") \
                .set_path(f"{url}") \
                .add_header("Cookie", f"csrftoken={self.csrf_cookie}; sessionid={self.session_cookie}") \
                .build()
        else:
            request = HttpRequestBuilder("GET") \
                .set_path(f"{url}") \
                .build()
        self.exchange(request)


    def login(self):
        """
        Performs login to the server.
        """
        request = HttpRequestBuilder("GET") \
            .set_path("/fakebook/") \
            .build()
        self.connect()
        self.exchange(request)

        csrf_match = re.search(fr'name="csrfmiddlewaretoken" value="([^"]+)"', self.body)
        token = csrf_match.group(1) if csrf_match else None

        next_url_match = re.search(fr'name="next" value="([^"]+)"', self.body)
        self.next_url = next_url_match.group(1) if next_url_match else None
        self.queue.put(self.next_url)

        self.parser.feed(self.body)

        self.send_post_request(token)

    def handle_flag_found(self):
        """
        Handles the event when a flag is found.
        """
        self.flags_found += 1
        if self.flags_found >= self.max_flags:
            sys.exit()  # Stop crawling if all flags are found

    def send_post_request(self, csrf_token):
        """
        Sends a POST request for login.

        Args:
        - csrf_token (str): The CSRF token for authentication.
        """
        if csrf_token is not None and self.next_url is not None:

            data_str = f"username={self.username}&password={self.password}&csrfmiddlewaretoken={csrf_token}&next=%2Ffakebook%2F"

            request = HttpRequestBuilder("POST") \
                .set_path(f"/accounts/login/?next={self.next_url}") \
                .add_header("Content-Type", "application/x-www-form-urlencoded") \
                .add_header("Cookie", f"csrftoken={csrf_token}; sessionid={self.session_cookie}") \
                .add_header("Origin", ORIGIN) \
                .add_header("Referer", f"https://www.3700.network/accounts/login/?next={self.next_url}") \
                .set_body(data_str) \
                .build()
            self.exchange(request)

    def parse_header(self, header_text: str):
        """
        Parses the HTTP header.

        Args:
        - header_text (str): The raw HTTP header.

        Returns:
        - dict: Parsed header information.
        """
        header_info = {}

        status_code_match = re.search(r'HTTP/1.0 (\d+)', header_text)

        if status_code_match:
            header_info["status"] = status_code_match.group(1)

        header_fields = re.findall(r'^(.*?): (.*)\r\n', header_text, re.MULTILINE)
        if header_fields:
            for field, value in header_fields:
                if field == "set-cookie":
                    if "csrftoken" in value:
                        match = re.search(r'csrftoken=(.*?);', value)
                        self.csrf_cookie = match.group(1)
                    elif "sessionid" in value:
                        match = re.search(r'sessionid=(.*?);', value)
                        self.session_cookie = match.group(1)
                else:
                    header_info[field] = value
        if len(header_info) == 0:
            raise ValueError("No Header Values were found. Check header input.")

        return header_info

    def crawl_all_pages(self):
        """
        Crawls all pages recursively.
        """
        while not self.queue.empty():
            next_url = self.queue.get()
            if next_url not in self.visited_pages and str(next_url).startswith("/fakebook/"):
                self.parse_pages(next_url)

    def parse_pages(self, next_url):
        """
        Parses HTML pages and extracts URLs.

        Args:
        - next_url (str): The URL of the page to parse.
        """
        request = HttpRequestBuilder("GET", host=self.server) \
            .set_path(f"{next_url}") \
            .add_header("Cookie", f"csrftoken={self.csrf_cookie}; sessionid={self.session_cookie}") \
            .build()

        self.exchange(request)
        self.visited_pages.add(next_url)
        self.parser.feed(self.body)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='crawl Fakebook')
    parser.add_argument('-s', dest="server", type=str, default=DEFAULT_SERVER, help="The server to crawl")
    parser.add_argument('-p', dest="port", type=int, default=DEFAULT_PORT, help="The port to use")
    parser.add_argument('username', type=str, help="The username to use")
    parser.add_argument('password', type=str, help="The password to use")
    args = parser.parse_args()
    sender = Crawler(args)
    sender.run()