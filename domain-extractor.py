#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: cbk914
import os
import re
import requests
import argparse
import socket
import json
import csv
import io
from bs4 import BeautifulSoup
from xml.etree import ElementTree as ET
import time
import tldextract
from urllib.parse import urlparse

def is_valid_domain(domain):
    try:
        socket.gethostbyname(domain)
        extracted = tldextract.extract(domain)
        return bool(extracted.domain and extracted.suffix)
    except socket.error:
        return False

def extract_domains_from_url(url, proxies=None):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
        }
        response = requests.get(url, headers=headers, proxies=proxies, timeout=10)
        response.raise_for_status()
        content = response.content.decode("utf-8")
        domains = extract_domains_from_text(content)
        return domains
    except Exception as e:
        print(f"Error fetching URL: {url} - {e}")
        return []

def extract_domains_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
    except FileNotFoundError:
        print(f"Error: File not found - {file_path}")
        return []

    domain_pattern = r'(?:(?:https?|ftp):\/\/)?(?:[\w\-]+(?:\.[\w\-]+)+)(?:\/[\w\-?=%.]+)?'
    domain_list = re.findall(domain_pattern, content)

    return domain_list

def extract_domains_from_zone_file(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
    except FileNotFoundError:
        print(f"Error: File not found - {file_path}")
        return []

    domain_pattern = r'\s+IN\s+A\s+(\S+)'
    domain_list = re.findall(domain_pattern, content)

    return domain_list

def check_domains(file_path, proxies=None):
    checked_domains = []

    try:
        with open(file_path, 'r') as file:
            domain_list = file.readlines()
    except FileNotFoundError:
        print(f"Error: File not found - {file_path}")
        return checked_domains

    start_time = time.time()
    for url in domain_list:
        url = url.strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        try:
            response = requests.get(url, timeout=10, proxies=proxies)
            status_code = response.status_code
            if 100 <= status_code < 400:
                checked_domains.append((url, status_code))
                print(f"[{status_code}] {url}")
        except (requests.exceptions.RequestException, IOError):
            pass

    print(f"\n[!] Finished in {int(time.time() - start_time)} second(s).")
    
    return checked_domains

def save_domains_to_file_in_format(domain_list, output_file, file_format):
    if file_format == "txt":
        with open(output_file, 'w') as file:
            for domain in domain_list:
                file.write(f'{domain}\n')
    elif file_format == "csv":
        with open(output_file, 'w', newline='') as file:
            writer = csv.writer(file)
            for domain in domain_list:
                writer.writerow([domain])
    elif file_format == "html":
        with open(output_file, 'w') as file:
            file.write("<html><head><title>Domains</title></head><body><table>\n")
            for domain in domain_list:
                file.write(f"<tr><td>{domain}</td></tr>\n")
            file.write("</table></body></html>")
    elif file_format == "xml":
        root = ET.Element("domains")
        for domain in domain_list:
            domain_element = ET.SubElement(root, "domain")
            domain_element.text = domain
        xml_data = ET.tostring(root, encoding="unicode", method="xml")
        with open(output_file, "w") as file:
            file.write(xml_data)
    elif file_format == "json":
        with open(output_file, "w") as file:
            json.dump(domain_list, file, indent=4)
    else:
        print("Invalid format")

def resolve_ip_to_domain(ip_address):
    try:
        domain = socket.gethostbyaddr(ip_address)[0]
        return domain
    except socket.gaierror as e:
        print(f"Error: Unable to resolve IP address - {ip_address}")
        return None

def main(args=None, proxies=None):
    parser = argparse.ArgumentParser(description="Extract domain names from a URL, file, or zone file and check the domains.")
    parser.add_argument('-u', '--url', action='append', help='URL containing domain names')
    parser.add_argument('-f', '--file', action='append', help='Input file containing domain names (txt, html, csv, json, xml)')
    parser.add_argument('-z', '--zone', action='append', help='Input zone file containing domain names')
    parser.add_argument('-c', '--check', help='Check domains in the provided file or URL and save the results to output file')
    parser.add_argument('-o', '--output', default='domains.txt', help='Output file to save the extracted domain names (default: domains.txt)')
    parser.add_argument("-F", "--format", help="Output file format (txt, csv, html, xml, json) (default: txt)", default="txt", required=False)
    parser.add_argument("-p", "--proxy", help="Proxy to be used in the format ip:port (default 127.0.0.1:8080)", default="127.0.0.1.80", required=False)

    args = parser.parse_args()

    url = args.url
    proxy = args.proxy
    timestamp = time.strftime("%Y%m%d-%H%M%S")

    if proxy:
        proxies = {
            "https": f"https://127.0.0.1:8080",
            "http": f"http://{proxy}",
            "https": f"https://{proxy}",
        }
    else:
        proxies = None
    
    if not any([args.url, args.file, args.zone, args.check]):
        parser.print_help()
        parser.error("Error: At least one of the following arguments is required: -u/--url, -f/--file, -z/--zone, -c/--check")

    # Check domains and save results to output file
    if args.check:
        output_file = os.path.splitext(args.check)[0] + f'_results_{timestamp}.csv'
        if args.check.startswith('http://') or args.check.startswith('https://'):
            domain_list = extract_domains_from_url(args.check, proxies)
            checked_domains = check_domains_list(domain_list, proxies)
        else:
            checked_domains = check_domains(args.check, proxies)
        save_domains_to_file_in_format(checked_domains, args.output, args.format)

    # Extract domain names from input sources
    domain_list = []

    if args.url:
        for u in args.url:
            url_domains = extract_domains_from_url(u, proxies)
            domain_list.extend(url_domains)

    if args.file:
        for f in args.file:
            file_domains = extract_domains_from_file(f)
            domain_list.extend(file_domains)

    if args.zone:
        for z in args.zone:
            zone_domains = extract_domains_from_zone_file(z)
            domain_list.extend(zone_domains)

    # Remove duplicate domain names
    domain_list = list(set(domain_list))

    # Save domain names to output file
    if domain_list:
        save_domains_to_file_in_format(domain_list, args.output, args.format)
        print(f"Domains have been saved to {args.output} in {args.format} format.")
    else:
        print("No domains found.")

if __name__ == "__main__":
    main()
