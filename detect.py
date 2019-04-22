#!/usr/bin/env python3
import requests
import argparse
import re
import subprocess
import urllib

def find_word(w):
    return re.compile(r'\b({0})\b'.format(w), flags=re.IGNORECASE).search

def keyword_scan(url, cookies, headers, text):
    # TODO: Implement fast pattern matching
    # https://yacin.nadji.us/classes/f16-adv-comp-sec/papers/15-zozzle.pdf
    result = [] # (type, name, version)

    # Server features -> nmap
    header_server_string = headers['Server']
    if find_word('apache')(header_server_string) is not None:
        server_suffix = header_server_string.split("/")[-1].split(" ")
        result.append(("server", "apache", server_suffix[0]))
        if len(server_suffix) > 1:
            result.append(("os", server_suffix[1].strip("()").lower(), ""))
    
    # Application features
    if find_word('wordpress')(text) is not None:
        result.append(("app", "wordpress", ""))
        # -> wpscan

    if find_word('php-nuke')(text) is not None:
        result.append(("app", "php-nuke", ""))

    # Database features -> sqlmap
    if find_word('mysql')(text) is not None:
        result.append(("db", "mysql", ""))

    if find_word('postgresql')(text) is not None:
        result.append(("db", "postgresql", ""))

    # OS features -> nmap
    if find_word('mac os')(text) is not None:
        result.append(("os", "mac_os", ""))

    if find_word('windows')(text) is not None:
        result.append(("os", "windows", ""))

    if find_word('linux')(text) is not None:
        result.append(("os", "linux", ""))

    if find_word('ubuntu')(text) is not None:
        result.append(("os", "linux", "ubuntu"))

    if find_word('fedora')(text) is not None:
        result.append(("os", "linux", "fedora"))

    if find_word('centos')(text) is not None:
        result.append(("os", "linux", "centos"))

    return result

def nmap_scan(url):
    parsed_url = urllib.parse.urlparse(url)
    host_port = parsed_url.netloc.split(":")
    host = host_port[0]
    port = ""
    if parsed_url.scheme == "http":
        port = "80"
    elif parsed_url.scheme == "https":
        port = "443"
    if len(host_port) > 1:
        port = host_port[1]

    nmap_result = subprocess.check_output(["nmap", "-p", port, "-sV", host, "-oG", "-"])
    output = {}
    for line in nmap_result.decode("utf-8").split("\n"):
        if len(line) > 0 and line.strip(" \t")[0] != '#':
            for field in line.split("\t"):
                key_value = field.split(":")
                key = key_value[0]
                value = key_value[1].strip(" ")
                if key == "Host":
                    output["ip_addr"] = value.split(" ")[0]
                    output["reverse_hostname"] = value.split(" ")[1].strip("()")
                elif key == "Ports":
                    port_fields = value.split("/")
                    if port_fields[0] == port:
                        output["server"] = port_fields[6]

    return output


def process_response(response):
    print("apparent_encoding: " + r.apparent_encoding)
    # print("content: " + r.content.decode(r.apparent_encoding))
    cookie_output = []
    for elem in r.cookies.items():
        cookie_output.append("\t" + elem[0] + "=" + elem[1])
    print("cookies: " + "\n".join(cookie_output))
    print("elapsed: " + str(r.elapsed.total_seconds()))
    print("encoding: " + r.encoding)
    header_output = []
    for k, v in r.headers.items():
        header_output.append("\t" + k + "=" + v)
    print("headers: \n" + "\n".join(header_output))
    print("status_code: " + str(r.status_code))
    # print("text: " + r.text)
    print("url: " + r.url)
    print("=" * 80)

    keywords = keyword_scan(r.url, r.cookies, r.headers, r.text)
    for keyword in keywords:
        print(" ".join(keyword))
    print("=" * 80)

    nmap_result = nmap_scan(r.url)
    for k, v in nmap_result.items():
        print(k + "=" + v)

    # TODO: (1) compare keywords and nmap_result, find inconsistence (if any)
    #        (2) launch specialized scanners (e.g. wpscan)

parser = argparse.ArgumentParser()
parser.add_argument("url")
args = parser.parse_args()

r = requests.get(args.url)

process_response(r)
