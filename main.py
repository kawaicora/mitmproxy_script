import argparse
import asyncio
import logging
from mitmproxy import options
from mitmproxy.tools.web.master import WebMaster
from RedirectAddon import *
from ProxyAddon import *


def parse_arguments():
    parser = argparse.ArgumentParser(description="Mitmproxy Multi-Mode Proxy")
    parser.add_argument("--mode", default="socks5", help="""
            The proxy server type(s) to spawn. Can be passed multiple times.

            Mitmproxy supports "regular" (HTTP), "transparent", "socks5", "reverse:SPEC",
            "upstream:SPEC", and "wireguard[:PATH]" proxy servers. For reverse and upstream proxy modes, SPEC
            is host specification in the form of "http[s]://host[:port]". For WireGuard mode, PATH may point to
            a file containing key material. If no such file exists, it will be created on startup.

            You may append `@listen_port` or `@listen_host:listen_port` to override `listen_host` or `listen_port` for
            a specific proxy mode. Features such as client playback will use the first mode to determine
            which upstream server to use.
            """)
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Proxy Listening host")

    return parser.parse_args()

async def start(mode=['regular', 'socks5',"wireguard"],listen_host:str="0.0.0.0"):
    logging.basicConfig(level=logging.INFO)
    
    # Mitmproxy configuration
    opts = options.Options(
        listen_host=listen_host,
        mode=mode,
        ssl_insecure=True,

    )
    
    m = WebMaster(opts)
    
    # Add custom addons as needed
    m.addons.add(ProxyAccess('config/proxy_config.yaml'))
    # m.addons.add(HostRedirect('config/host_redirect_config.yaml'))
    # m.addons.add(PathRedirect('config/path_redirect_config.yaml'))
    # m.addons.add(TCPUDPRedirect('config/tcp_udp_redirect_config.yaml'))
    
    try:
        
        await m.run()
    except KeyboardInterrupt:
        logging.info("Stopping mitmproxy...")
        await m.shutdown()


if __name__ == "__main__":
    # args = parse_arguments()
    
    asyncio.run(start())