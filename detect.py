#!/usr/bin/env python3
import requests
import argparse
import re
import subprocess
import urllib
import code

def find_word(w):
    return re.compile(r'\b({0})\b'.format(w), flags=re.IGNORECASE).search

def keyword_scan(url, cookies, headers, text):
    # TODO: Implement fast pattern matching
    # https://yacin.nadji.us/classes/f16-adv-comp-sec/papers/15-zozzle.pdf
    result = set() # (type, name, version)

    # Server features -> nmap
    header_server_string = headers['Server']
    if find_word('apache')(header_server_string) is not None:
        header_server_fields =  header_server_string.split("/")
        server_name = header_server_fields[0].strip(" \t").lower()
        server_suffix = header_server_fields[-1].split(" ")
        if server_name == "apache":
            result.add(("server", "apache_httpd", server_suffix[0]))
            if len(server_suffix) > 1:
                result.add(("os", server_suffix[1].strip("()").lower(), ""))
    
    # Application features
    if find_word('wordpress')(text) is not None:
        result.add(("app", "wordpress", ""))
        # -> wpscan

    if find_word('php-nuke')(text) is not None:
        result.add(("app", "php-nuke", ""))

    # Database features -> sqlmap
    if find_word('mysql')(text) is not None:
        result.add(("db", "mysql", ""))

    if find_word('postgresql')(text) is not None:
        result.add(("db", "postgresql", ""))

    # OS features -> nmap
    if find_word('mac os')(text) is not None:
        result.add(("os", "mac_os", ""))

    if find_word('windows')(text) is not None:
        result.add(("os", "windows", ""))

    if find_word('linux')(text) is not None:
        result.add(("os", "linux", ""))

    if find_word('ubuntu')(text) is not None:
        result.add(("os", "linux", "ubuntu"))

    if find_word('fedora')(text) is not None:
        result.add(("os", "linux", "fedora"))

    if find_word('centos')(text) is not None:
        result.add(("os", "linux", "centos"))

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
    output = set()
    for line in nmap_result.decode("utf-8").split("\n"):
        if len(line) > 0 and line.strip(" \t")[0] != '#':
            for field in line.split("\t"):
                key_value = field.split(":")
                key = key_value[0]
                value = key_value[1].strip(" ")
                if key == "Host":
                    # output["ip_addr"] = value.split(" ")[0]
                    # output["reverse_hostname"] = value.split(" ")[1].strip("()")
                    pass
                elif key == "Ports":
                    port_fields = value.split("/")
                    if port_fields[0] == port:
                        server_type_fields = port_fields[6].split(" ")
                        if server_type_fields[0] == "Apache":
                            if len(server_type_fields) > 1 and server_type_fields[1] == "httpd":
                                if len(server_type_fields) > 2:
                                    output.add(("server", "apache_httpd", server_type_fields[2]))
                                # TODO: add OS type detection

    return output

def wfuzz_scan(url):
    wfuzz_result = subprocess.check_output(["wfuzz", "-w", "data/wfuzz_list.txt", "--hc", "404", url + ("/FUZZ" if url[-1] != "/" else "FUZZ")])
    output = set()
    for line in wfuzz_result.decode("utf-8").split("\n"):
        fields = line.split("\t")
        if len(fields) == 4:
            path = fields[-1][3:-5]
            if path == "SiteServer":
                output.add(("server", "iis", ""))
            elif path[:5] == "W3SVC":
                output.add(("server", "iis", ""))
            elif path == "WEB-INF":
                output.add(("language", "java", ""))
            elif path == "apache":
                output.add(("server", "apache_httpd", ""))
            elif path == "asp":
                output.add(("language", "asp", ""))
            elif path == "aspadmin":
                output.add(("language", "asp", ""))
            elif path == "cfdocs":
                output.add(("language", "cfm", ""))
            elif path == "dbase":
                output.add(("db", "dbase", ""))
            elif path == "dev60cgi":
                output.add(("db", "oracle", ""))
            elif path == "docs41":
                output.add(("language", "java", ""))
            elif path == "docs51":
                output.add(("language", "java", ""))
            elif path == "iis":
                output.add(("server", "iis", ""))
            elif path == "jdbc":
                output.add(("language", "java", ""))
            elif path == "jsp":
                output.add(("language", "java", ""))
            elif path == "oradata":
                output.add(("db", "oracle", ""))
            elif path == "phpmyadmin":
                output.add(("language", "php", ""))
            elif path == "phpMyAdmin":
                output.add(("language", "php", ""))
            elif path == "index.asp":
                output.add(("language", "asp", ""))
            elif path == "index.aspx":
                output.add(("language", "asp", ""))
            elif path == "index.php":
                output.add(("language", "php", ""))
            elif path == "index.jsp":
                output.add(("language", "java", ""))
            elif path == "index.cfm":
                output.add(("language", "cfm", ""))
    return output

def process_response(response):
    print("apparent_encoding: " + r.apparent_encoding)
    # print("content: " + r.content.decode(r.apparent_encoding))
    cookie_output = []
    for elem in r.cookies.items():
        cookie_output.add("\t" + elem[0] + "=" + elem[1])
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

    keyword_result = keyword_scan(r.url, r.cookies, r.headers, r.text)
    nmap_result = nmap_scan(r.url)
    wfuzz_result = wfuzz_scan(r.url)

    # TODO: (1) launch specialized scanners (e.g. wpscan)

    all_result = keyword_result.union(nmap_result, wfuzz_result)

    result_dict = {}
    for keyword in all_result:
        if keyword[0] not in result_dict:
            result_dict[keyword[0]] = {}
        if keyword[1] not in result_dict[keyword[0]]:
            result_dict[keyword[0]][keyword[1]] = set()
        if keyword[2] != "" and keyword[2] not in result_dict[keyword[0]][keyword[1]]:
            result_dict[keyword[0]][keyword[1]].add(keyword[2])
        print(" ".join(keyword))

    print("=" * 80)

    mutual_exclusion_groups = [
        [("os", "windows", ""), ("os", "linux", ""), ("os", "mac_os", "")],
        [("db", "mysql", ""), ("db", "postgresql", ""), ("db", "oracle", ""), ("db", "mssql", "")],
        [("language", "asp", ""), ("language", "php", ""), ("language", "java", ""), ("language", "cfm", "")],
        [("server", "apache_httpd", ""), ("server", "nginx", ""), ("server", "iis", "")],
        [("os", "linux", ""), ("db", "mssql", "")],
        [("os", "linux", ""), ("language", "asp", "")],
        [("os", "linux", ""), ("server", "iis", "")],
        [("language", "java", ""), ("server", "apache_httpd", ""), ("server", "nginx", ""), ("server", "iis", "")],
        [("language", "asp", ""), ("server", "apache_httpd", ""), ("server", "nginx", "")],
    ]

    inconsistence_count = 0
    violated_rules = set()

    # Rule 1: no more than 1 elem in every mutual exclusion group
    for group in mutual_exclusion_groups:
        found = set()
        for keyword in group:
            if keyword[0] in result_dict:
                if keyword[1] in result_dict[keyword[0]]:
                    if keyword[2] == "" or keyword[2] in result_dict[keyword[0]][keyword[1]]:
                        found.add(keyword)
        if len(found) > 1:
            violated_rules.add(tuple(sorted(found)))
            inconsistence_count += 1

    # Rule 2: no more than one version for every software
    keyword_buckets = {}
    for keyword in all_result:
        if keyword[0] not in keyword_buckets:
            keyword_buckets[keyword[0]] = {}
        if keyword[1] not in keyword_buckets[keyword[0]]:
            keyword_buckets[keyword[0]][keyword[1]] = set()
        if keyword[2] != "":
            keyword_buckets[keyword[0]][keyword[1]].add(keyword)

    for k1, v1 in keyword_buckets.items():
        for k2, v2 in v1.items():
            if len(v2) > 1:
                violated_rules.add(tuple(sorted(v2)))

    for keyword in sorted(violated_rules):
        print(keyword)

parser = argparse.ArgumentParser()
parser.add_argument("url")
args = parser.parse_args()

r = requests.get(args.url)

process_response(r)
