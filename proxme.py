import http.client
import socketserver 
import http.server
import urllib
import sys
import urllib.error
import urllib.request
import re

HOST_REGEX = "http(s?):\\/\\/(([a-zA-Z0-9\\.-]+)(:[0-9]+))\\/?"
HEADER_REGEX = "(.*?):(.*)"

# TODO : Build GUI to input parameters
PORT = int(sys.argv[1])
TARGET = sys.argv[2]
HOST = re.search(HOST_REGEX, TARGET).group(2)
ORIGIN = sys.argv[3] if len(sys.argv) > 3 else '*' 
if ORIGIN == '*':
    print("WARNING: You are potentially exposing a local resource to malicious Websites")

# Proxy Implementation on Allow-Steroids
class ProxMe(http.server.SimpleHTTPRequestHandler):
    
    def do_GET(self) -> None:
        self.proxy_request()

    def do_POST(self) -> None:
        # TODO implement DATA handling
        self.proxy_request()

    def do_OPTIONS(self) -> None:
        try:
            self.proxy_request()
        except urllib.error.HTTPError as err:
            # If the TARGET doesn't implement OPTIONS
            if err.status == http.HTTPStatus.NOT_IMPLEMENTED:
                self.send_response(http.HTTPStatus.OK)
                self.add_allow_headers()
                self.end_headers()

    # Proxies a Request to the supplied target
    def proxy_request(self) -> None:
        url=TARGET + '/' + self.path[1:]
        request = urllib.request.Request(url, data=None)
        # pass and adjust headers (change Host)
        for key, value in self.headers.items():
            if key.lower() == 'Host'.lower():
                value = HOST
            request.add_header(key, value)
        try:
            # actual request to TARGET happening here
            response = urllib.request.urlopen(request)
        except urllib.error.HTTPError as httpError:
            # special handling for APIs that require Authorization for Preflight (which is wrong)
            if self.command == http.HTTPMethod.OPTIONS and httpError.status == 401:
                raise urllib.error.HTTPError(url, http.HTTPStatus.NOT_IMPLEMENTED, "OPTIONS not implemented", httpError.headers, httpError.file)
            else:
                # we can use regular HTTPErrors as response (they share the same necessary attributes)
                response = httpError
        except urllib.error.URLError as urlError:
            print("URL Error, didn't pass request for URL:", url)
            raise urlError
        self.send_response(response.status, response.msg)
        # transfer Headers from TARGET's response to Client repsonse
        headers : http.client.HTTPMessage = response.headers
        for key, value in headers.items():
            self.send_header(key, value)
        # set allow headers, if not present
        self.add_allow_headers()
        self.end_headers()
        self.copyfile(response, self.wfile)
    
    # Adds Allow Headers if not present
    def add_allow_headers(self) -> None:
        allow_origin = self.check_header('Access-Control-Allow-Origin') 
        if not allow_origin:
            allow_origin = self.headers.get('Origin')
            if allow_origin and (ORIGIN == '*' or ORIGIN == allow_origin):
                self.send_header('Access-Control-Allow-Origin', allow_origin)
        allow_headers = self.check_header('Access-Control-Allow-Headers') 
        if not allow_headers:
            allow_headers = self.headers.get('Access-Control-Request-Headers')
            if allow_headers:
                self.send_header('Access-Control-Allow-Headers', allow_headers)
        allow_method = self.check_header('Access-Control-Allow-Method') 
        if not allow_method:
            allow_method = self.headers.get('Access-Control-Request-Method')
            if allow_method:
                self.send_header('Access-Control-Allow-Method', allow_method)


    # Check if a header already has been set. (Only works before flush has been called)
    def check_header(self, key:str) -> str:
        if not hasattr(self, '_headers_buffer'):
            self._headers_buffer = []
        for line in self._headers_buffer:
            line = line.decode('latin-1', 'strict')
            if not line.startswith('HTTP/'):
                match = re.search(HEADER_REGEX, line)
                if match.group(1) == key:
                    return match.group(2)
        return None

# creates the actual server, go with threaded variant to allow for a bit parallel request handling
httpd = socketserver.ThreadingTCPServer(('', PORT), ProxMe)

print ("Now serving at", str(PORT), " for ", TARGET, " with CORS-Policy for ", ORIGIN)

try:
    # start serving
    httpd.serve_forever()
except Exception:
    # to ensure shutdown on whatever unexpected happens
    httpd.shutdown()