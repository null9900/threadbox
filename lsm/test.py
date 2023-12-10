from lib import PERM, sandbox_ps
from http.server import HTTPServer, SimpleHTTPRequestHandler
import subprocess

sandbox_ps();

def open_server_port_80():
    httpd = HTTPServer(('localhost', 80), SimpleHTTPRequestHandler)
    print("server is working on 80");

@PERM("bind_socket",3000)
def open_server_port_3000():
    httpd = HTTPServer(('localhost', 3000), SimpleHTTPRequestHandler)
    print("server is working on port 3000");

@PERM("fork",None)
def create_another_process():
    subprocess.Popen(["sleep", "1"])

@PERM("bind_socket",80)
def main():
    open_server_port_80();
    open_server_port_3000();
    create_another_process();

main()
