#!/usr/bin/env python3
# coding: utf-8
import urllib.request
import urllib.parse
import urllib.error
import sys
from scapy.all import *

# import socket
# timeout in seconds
# timeout = 10
# socket.setdefaulttimeout(timeout)

VERSION = "v0.1"
USERAGENT = "bydpi_checker " + VERSION

proxy_addr = 'proxy.antizapret.prostovpn.org:3128'

white_list = (
    "https://www.prior.by",
    "https://beltelecom.by",
    # "https://lurkmore.to",
)

black_list = (
    # "https://naviny.media",
    "https://naviny.by",
    "https://lurkmore.to",
    # "https://beltelecom.by",
    # "https://a2day.net",
    # "https://govkino.ru",
    # "https://charter97.org",
)

def get_ip():
    try:
        request = urllib.request.Request("https://api.ipify.org/?format=text",
                                         headers={"User-Agent": USERAGENT}
                                         )
        ip = urllib.request.urlopen(request, timeout=10).read()
        ip = ip.decode('utf-8')
        if ip:
            return (ip)
    except Exception:
        return

def _get_url(url, proxy=None):
    parsed_url = list(urllib.parse.urlsplit(url))
    host = parsed_url[1]

    req = urllib.request.Request(url)
    req.add_header('User-Agent', USERAGENT)
    if proxy:
        req.set_proxy(proxy, 'http')
    try:
        response = urllib.request.urlopen(req, timeout=10).read()
        # print(response)
        return 1
    except urllib.error.URLError as e:
        # print(e.reason)
        return 2

def check_urls(sites_list, use_proxy=None, white=True):
    proxy = proxy_addr
    checkresults = []
    site_list = list(sites_list)
    for site in sorted(site_list):
        if use_proxy:
            # print("Accessing via proxy: " + site)
            s = _get_url(site, proxy)
        else:
            # print("Accessing: " + site)
            s = _get_url(site)
        checkresults.append(s)
    if white:
        if 2 in checkresults:
            # Blocked
            # print("white list is blocked, something went wrong")
            return 2
        else:
            # print("all is ok")
            return 1
    else:
        if 1 in checkresults:
            # print("black list is accessible, that's not ok")
            return 2
        else:
            # print("all is ok")
            return 1


def passive_dpi_detect():
    # Most of Passive DPIs catched by this defaults:
    # None IP flags - 0x0000, IP Identification is always 0x0001, TCP flags - 0x004 - RST (for HTTPS), 0x025 - ACK,PUSH,FIN (for HTTP)
    passive_dpi_filter = lambda s: s[IP].flags == 0 and s[IP].id == 1 and s[TCP].flags == 4
    # sc = AsyncSniffer(filter="host lurkmore.to and port 443", count=10, lfilter = passive_dpi_filter, prn=lambda x:x.summary())  # sniff packets on port 443
    sc = AsyncSniffer(filter="host lurkmore.to and port 443", count=10, lfilter = passive_dpi_filter)  # sniff packets on port 443, silent mode
    sc.start()
    s = _get_url("https://lurkmore.to")
    results = sc.stop()
    if results:
        # print("Passive type DPI detected")
        return 1
    else:
        # print("Another type of DPI detected")
        return 2
    # results.show()

def main():
    my_ip = get_ip()
    print(my_ip)
    print("Trying white-list hosts:\t", end =" ")
    white = check_urls(white_list, use_proxy=False, white=True)
    if white == 1:
        print("Ok")
    else:
        print("Smth wrong")
    print("Trying black-list hosts:\t", end =" ")
    black = check_urls(black_list, use_proxy=False, white=False)
    if black == 1:
        print("Ok")
    else:
        print("Smth wrong")
    # # check_urls(black_list, use_proxy=False)
    if white == 1 and black == 1:
        dpi_type = passive_dpi_detect()
    if dpi_type == 1:
        print("Passive type DPI detected")
    else:
        print("Another type of DPI detected")

if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        sys.exit(1)
