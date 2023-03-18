#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: cbk914
import re
import requests
import argparse
import socket
import json
import csv
from bs4 import BeautifulSoup
from xml.etree import ElementTree as ET
import threading
import time

def extract_domains_from_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        content = response.text
    except requests.exceptions.RequestException as e:
        print(f"Error while fetching URL: {e}")
        return []

    domain_pattern = r'(?:(?:https?|ftp):\/\/)?[\w/\-?=%.]+\.[\w/\-?=%.]+'
    domain_list = re.findall(domain_pattern, content)

    # If no domains are found in the content, check the URL domain itself
    if not domain_list:
        url_domain = re.match(domain_pattern, url)
        if url_domain:
            domain_list.append(url_domain.group(0))

    return domain_list

def extract_domains_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
    except FileNotFoundError:
        print(f"Error: File not found - {file_path}")
        return []

    file_extension = file_path.split('.')[-1].lower()

    if file_extension == 'html':
        try:
            soup = BeautifulSoup(content, 'html.parser')
            content = soup.get_text()
        except html.parser.HTMLParseError as e:
            print(f"Error while parsing HTML content: {e}")

    elif file_extension == 'json':
        try:
            data = json.loads(content)
            content = json.dumps(data, indent=4)
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON file - {file_path}")
            return []

    elif file_extension == 'csv':
        try:
            data = list(csv.reader(content.splitlines()))
            content = "\n".join([",".join(row) for row in data])
        except csv.Error:
            print(f"Error: Invalid CSV file - {file_path}")
            return []

    elif file_extension == 'xml':
        try:
            tree = ET.ElementTree(ET.fromstring(content))
            content = ET.tostring(tree.getroot(), encoding='unicode')
        except ET.ParseError:
            print(f"Error: Invalid XML file - {file_path}")
            return []

    domain_pattern = r'(?:(?:https?|ftp):\/\/)?[\w/\-?=%.]+\.[\w/\-?=%.]+'
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

def check_domains(file_path):
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
            response = requests.get(url, timeout=10)
            status_code = response.status_code
            if 100 <= status_code < 400:
                checked_domains.append((url, status_code, []))
                print(f"[{status_code}] {url}")
                if response.history:
                    for res in response.history:
                        print(f"\tRedirected To: [Response:{res.status_code}] {res.url}")
                        checked_domains[-1][2].append((res.url, res.status_code))
                    print(f"\tFinal Redirection: [Response:{response.status_code}] {response.url}")
        except (requests.exceptions.RequestException, IOError):
            pass

    print(f"\n[!] Finished in {int(time.time() - start_time)} second(s).")
    return checked_domains

def save_checked_domains_to_file(checked_domains, output_file):
    with open(output_file, 'w') as file:
        for url, status_code, redirects in checked_domains:
            file.write(f"[{status_code}] {url}\n")
            if redirects:
                for redirect_url, redirect_status_code in redirects:
                    file.write(f"\tRedirected To: [Response:{redirect_status_code}] {redirect_url}\n")

def extract_domains_from_text_file(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
    except FileNotFoundError:
        print(f"Error: File not found - {file_path}")
        return []

    domain_pattern = r'(?:(?:https?|ftp):\/\/)?[\w/\-?=%.]+\.[\w/\-?=%.]+'
    domain_list = re.findall(domain_pattern, content)

    return domain_list

def save_domains_to_file(domain_list, output_file):
    with open(output_file, 'w') as file:
        for domain in domain_list:
            file.write(f'{domain}\n')

def resolve_ip_to_domain(ip_address):
    try:
        domain = socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        print(f"Error: Unable to resolve IP address - {ip_address}")
        return None

    return domain

def main():
    parser = argparse.ArgumentParser(description="Extract domain names from a URL, file, or zone file and check the domains.")
    parser.add_argument('-u', '--url', action='append', help='URL containing domain names')
    parser.add_argument('-f', '--file', action='append', help='File containing domain names (txt, html, csv, json, xml)')
    parser.add_argument('-z', '--zone', action='append', help='Zone file containing domain names')
    parser.add_argument('-c', '--check', help='Check domains in the provided file')
    parser.add_argument('-o', '--output', default='domains.txt', help='Output file to save the extracted domain names')
    args = parser.parse_args()

    if not any([args.url, args.file, args.zone, args.check]):
        parser.print_help()
        parser.error("Error: At least one of the following arguments is required: -u/--url, -f/--file, -z/--zone, -c/--check")

    if args.check:
        checked_domains = check_domains(args.check)
        save_checked_domains_to_file(checked_domains, 'domains_checked.txt')

    all_domains = []
    if args.url:
        for url in args.url:
            domains_from_url = extract_domains_from_url(url)
            all_domains.extend(domains_from_url)

    if args.file:
        for file_path in args.file:
            domains_from_file = extract_domains_from_file(file_path)
            all_domains.extend(domains_from_file)

    if args.zone:
        for zone_file in args.zone:
            domains_from_zone_file = extract_domains_from_zone_file(zone_file)
            all_domains.extend(domains_from_zone_file)

    unique_domains = list(set(all_domains))
    save_domains_to_file(unique_domains, args.output)

    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    ip_addresses = list(set(re.findall(ip_pattern, ' '.join(unique_domains))))

    resolved_domains = []
    for ip in ip_addresses:
        domain = resolve_ip_to_domain(ip)
        if domain:
            resolved_domains.append(domain)

    unique_resolved_domains = list(set(resolved_domains))
    save_domains_to_file(unique_resolved_domains, 'resolved.txt')

    if unique_domains:
        print(f"Domains have been saved to {args.output}")
    else:
        print("No domains found.")

    if unique_resolved_domains:
        print(f"Resolved domains from IP addresses have been saved to resolved.txt")
    else:
        print("No resolved domains from IP addresses.")

if __name__ == "__main__":
    main()
