from lib import PERM, sandbox_ps
from http.server import HTTPServer, SimpleHTTPRequestHandler
import subprocess

sandbox_ps();

@PERM("net")
def open_server_port_3000():
    httpd = HTTPServer(('localhost', 3000), SimpleHTTPRequestHandler)
    print("server is working on port 3000");

@PERM("proc")
def create_another_process():
    subprocess.Popen(["sleep", "1"])
    print("forking is working")

def main():
    open_server_port_3000();
    create_another_process();
    print("done testing");

main()
