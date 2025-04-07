import re
import socket
import threading
import yaml
from mitmproxy import http



class TCPUDPRedirect:
    def __init__(self, config_path):
        with open(config_path, 'r',encoding='utf-8') as file:
            self.config = yaml.safe_load(file)

    def start(self):
        try:
            for rule in self.config:
                if rule['protocol'] == 'udp':
                    threading.Thread(target=self.handle_udp, args=(rule,)).start()
                if rule['protocol'] == 'tcp':
                    threading.Thread(target=self.handle_tcp, args=(rule,)).start()
        except Exception as e:
            pass
    def handle_udp(self, rule):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind((rule['from_host'], rule['from_port']))
        print(f"UDP Proxy listening on {rule['from_host']}:{rule['from_port']}")

        while True:
            data, addr = server.recvfrom(4096)
            print(f"Received data from {addr}")
            server.sendto(data, (rule['to_host'], rule['to_port']))
    
    def handle_tcp(self, rule):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((rule['from_host'], rule['from_port']))
        server.listen(5)
        print(f"TCP Proxy listening on {rule['from_host']}:{rule['from_port']}")

        while True:
            client_socket, addr = server.accept()
            print(f"Accepted connection from {addr}")
            threading.Thread(target=self.forward_tcp, args=(client_socket, rule)).start()

    def forward_tcp(self, client_socket, rule):
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((rule['to_host'], rule['to_port']))

        threading.Thread(target=self.pipe, args=(client_socket, remote_socket)).start()
        threading.Thread(target=self.pipe, args=(remote_socket, client_socket)).start()

    def pipe(self, src, dst):
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.send(data)
        src.close()
        dst.close()



class HostRedirect:
    def __init__(self, config_path):
        with open(config_path, 'r',encoding='utf-8') as file:
            self.config = yaml.safe_load(file)
            
    def request(self, flow: http.HTTPFlow) -> None:
        try:
            for rule in self.config:
                pattern = re.escape(rule['from']).replace(r'\*', '.*')
                if re.match(pattern, flow.request.pretty_host):
                    if rule['https_to_http']:
                        flow.request.scheme = 'http'
                    
                    flow.request.host = rule['to'].split(':')[0]
                    flow.request.port = int(rule['to'].split(':')[1])
                    break
        except Exception as e:
            pass
class PathRedirect:
    def __init__(self, config_path):
        with open(config_path, 'r',encoding='utf-8') as file:
            self.config = yaml.safe_load(file)

    def request(self, flow: http.HTTPFlow) -> None:
        try:
            for rule in self.config:
                
                pattern = re.escape(rule['path']).replace(r'\*', '.*')
                if re.match(pattern, flow.request.path):
                    if rule['http_to_https']:
                        flow.request.scheme = 'https'
                    flow.request.host = rule['to'].split(':')[0]
                    flow.request.port = int(rule['to'].split(':')[1])
                    return
        except Exception as e:
            pass