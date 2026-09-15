# HTTP/1.1 — RFC 9110, RFC 9112
#
# Text, so the payload hex is just the request line, headers and the blank line
# that ends them. 0d0a is CRLF.

name     HTTP request and response

# "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\n\r\n"
packet   tcp 10.0.0.1:51000 > 10.0.0.2:80  474554202f696e6465782e68746d6c20485454502f312e310d0a486f73743a206578616d706c652e636f6d0d0a557365722d4167656e743a206375726c2f382e300d0a0d0a
proto    HTTP
info~    GET /index.html
str      http.method     GET
str      http.uri        /index.html
str      http.version    HTTP/1.1
# Header names are normalised to lowercase with underscores, so "User-Agent"
# is reachable as http.headers.user_agent.
str      http.headers.host        example.com
str      http.headers.user_agent  curl/8.0
absent   http.status_code

# "HTTP/1.1 404 Not Found\r\nServer: nginx\r\nContent-Length: 0\r\n\r\n"
packet   tcp 10.0.0.2:80 > 10.0.0.1:51000  485454502f312e3120343034204e6f7420466f756e640d0a5365727665723a206e67696e780d0a436f6e74656e742d4c656e6774683a20300d0a0d0a
proto    HTTP
info~    404
str      http.status_code  404
str      http.reason       Not Found
str      http.headers.server  nginx
absent   http.method
