from mitmproxy import http
import re
import yaml


class ProxyAccess:
    def __init__(self, config_path):
        with open(config_path, 'r') as file:
            self.config = yaml.safe_load(file)

    def request(self, flow: http.HTTPFlow) -> None:
        try:
            for rule in self.config:
                pattern = re.escape(rule['from']).replace(r'\*', '.*')
                if re.match(pattern, flow.request.pretty_host):
                    proxy = rule['proxy']
                    proxy_type = rule['type']
                    if proxy_type == 'socks5':
                        flow.live.change_upstream_proxy_server(f"socks5://{proxy}")
                    else:
                        flow.live.change_upstream_proxy_server(f"http://{proxy}")
                    break
        except Exception as e:
            pass