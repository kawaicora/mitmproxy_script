import yaml
import re
import asyncio
from aiohttp import web
from dnslib import DNSRecord, QTYPE, RR, A

class DNSResolver:
    def __init__(self, config_path):
        with open(config_path, 'r') as file:
            self.config = yaml.safe_load(file)

    def resolve(self, qname, qtype):
        reply = DNSRecord()
        for rule in self.config:
            pattern = re.escape(rule['host']).replace(r'\*', '.*')
            if re.match(pattern, qname):
                reply.add_answer(RR(qname, getattr(QTYPE, qtype), rdata=A(rule['ip'])))
                break
        return reply

async def handle_request(request):
    resolver = request.app['resolver']
    data = await request.read()
    dns_request = DNSRecord.parse(data)
    qname = str(dns_request.q.qname)
    qtype = QTYPE[dns_request.q.qtype]
    reply = resolver.resolve(qname, qtype)
    return web.Response(body=reply.pack(), content_type='application/dns-message')

async def init_app(config_path):
    resolver = DNSResolver(config_path)
    app = web.Application()
    app['resolver'] = resolver
    app.router.add_post('/dns-query', handle_request)
    return app

if __name__ == "__main__":
    config_path = 'dns_config.yaml'
    app = init_app(config_path)
    web.run_app(app, port=443, ssl_context=('path/to/your/cert.pem', 'path/to/your/key.pem'))