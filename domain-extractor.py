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
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from xml.etree import ElementTree as ET

BANNER = r"""
______                      _         _____     _                  _             
|  _  \                    (_)       |  ___|   | |                | |            
| | | |___  _ __ ___   __ _ _ _ __   | |____  _| |_ _ __ __ _  ___| |_ ___  _ __ 
| | | / _ \| '_ ` _ \ / _` | | '_ \  |  __\ \/ / __| '__/ _` |/ __| __/ _ \| '__|
| |/ / (_) | | | | | | (_| | | | | | | |___>  <| |_| | | (_| | (__| || (_) | |   
|___/ \___/|_| |_| |_|\__,_|_|_| |_| \____/_/\_\\__|_|  \__,_|\___|\__\___/|_|   
                                                                                 
"""

logging.basicConfig(level=logging.INFO, format="%(asctime)s: %(message)s")

def extract_domains_from_url(url):
    logging.info(f"Extracting elements and domains from URL: {url}")
    try:
        response = requests.get(url)
        response.raise_for_status()
        content = response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching URL {url}: {e}")
        return []

    domain_pattern = r'(?:(?:https?|ftp):\/\/)?(?:[\w\-]+(?:\.[\w\-]+)+)(?:\/[\w\-?=%.]+)?'
    return re.findall(domain_pattern, content)

def extract_domains_from_file(file_path):
    logging.info(f"Extracting domains from file: {file_path}")
    try:
        with open(file_path, 'r') as file:
            content = file.read()
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return []

    file_extension = file_path.split('.')[-1].lower()

    if file_extension == 'html':
        try:
            soup = BeautifulSoup(content, 'html.parser')
            content = soup.get_text()
        except Exception as e:
            logging.error(f"Error parsing HTML content: {e}")
            return []

    elif file_extension == 'json':
        try:
            data = json.loads(content)
            content = json.dumps(data, indent=4)
        except json.JSONDecodeError:
            logging.error(f"Invalid JSON file: {file_path}")
            return []

    elif file_extension == 'csv':
        try:
            data = list(csv.reader(content.splitlines()))
            content = "\n".join([",".join(row) for row in data])
        except csv.Error:
            logging.error(f"Invalid CSV file: {file_path}")
            return []

    elif file_extension == 'xml':
        try:
            tree = ET.ElementTree(ET.fromstring(content))
            content = ET.tostring(tree.getroot(), encoding='unicode')
        except ET.ParseError:
            logging.error(f"Invalid XML file: {file_path}")
            return []

    domain_pattern = r'(?:(?:https?|ftp):\/\/)?(?:[\w\-]+(?:\.[\w\-]+)+)(?:\/[\w\-?=%.]+)?'
    return re.findall(domain_pattern, content)

def extract_domains_from_zone_file(file_path, domains):
    logging.info(f"Extracting domains from zone file: {file_path}")
    try:
        with open(file_path, 'r') as file:
            content = file.read()
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return []

    domain_pattern = r'\s+IN\s+A\s+(\S+)'
    domain_list = re.findall(domain_pattern, content)

    for domain in domain_list:
        if domain not in domains:
            domains.append(domain)

    return domains

def check_domain(url):
    logging.info(f"Checking domain: {url}")
    try:
        response = requests.get(url, timeout=10)
        status_code = response.status_code
        if 100 <= status_code < 400:
            checked_domain = (url, status_code, [])
            redirects = []
            if response.history:
                for res in response.history:
                    redirects.append((res.url, res.status_code))
            checked_domain = (url, status_code, redirects)
            return checked_domain
    except (requests.exceptions.RequestException, IOError):
        logging.error(f"Error checking domain: {url}")
    return None

def check_domains(file_path, output_file, max_workers=10):
    logging.info(f"Checking domains from file: {file_path}")
    checked_domains = []

    try:
        with open(file_path, 'r') as file:
            domain_list = [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return checked_domains

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(check_domain, url): url for url in domain_list}

        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                checked_domain = future.result()
                if checked_domain:
                    checked_domains.append(checked_domain)
                    url, status_code, redirects = checked_domain
                    logging.info(f"[{status_code}] {url}")
                    if redirects:
                        for redirect_url, redirect_status_code in redirects:
                            logging.info(f"\tRedirected To: [Response:{redirect_status_code}] {redirect_url}")
            except Exception as e:
                logging.error(f"Error checking {url}: {e}")

    logging.info(f"Finished in {int(time.time() - start_time)} second(s).")
    save_checked_domains_to_file(checked_domains, output_file)
    return checked_domains

def save_checked_domains_to_file(checked_domains, output_file):
    if not checked_domains:
        logging.warning(f"No checked domains to save in {output_file}")
        return

    logging.info(f"Saving checked domains to file: {output_file}")
    with open(output_file, 'w') as file:
        for url, status_code, redirects in checked_domains:
            file.write(f"[{status_code}] {url}\n")
            if redirects:
                for redirect_url, redirect_status_code in redirects:
                    file.write(f"\tRedirected To: [Response:{redirect_status_code}] {redirect_url}\n")

def save_domains_to_file(domain_list, output_file):
    if not domain_list:
        logging.warning(f"No domains to save in {output_file}")
        return

    logging.info(f"Saving domains to file: {output_file}")
    with open(output_file, 'w') as file:
        for domain in domain_list:
            file.write(f'{domain}\n')

def resolve_ip_to_domain(ip_address):
    logging.info(f"Resolving IP to domain: {ip_address}")
    try:
        domain = socket.gethostbyaddr(ip_address)[0]
        return domain
    except socket.herror:
        logging.error(f"Unable to resolve IP address: {ip_address}")
    return None

def main():
    parser = argparse.ArgumentParser(description=f"{BANNER}\nExtract domain names from a URL, file, or zone file and check the domains.", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-u', '--url', action='append', help='URL containing domain names')
    parser.add_argument('-f', '--file', action='append', help='File containing domain names (txt, html, csv, json, xml)')
    parser.add_argument('-z', '--zone', action='append', help='Zone file containing domain names')
    parser.add_argument('-c', '--check', nargs='?', const=True, help='Check domains in the provided file or the current generated file and save the results to output file')
    parser.add_argument('-o', '--output', default='domains.txt', help='Output file to save the extracted domain names (default: domains.txt)')
    args = parser.parse_args()

    if not any([args.url, args.file, args.zone, args.check]):
        parser.print_help()
        parser.error("Error: At least one of the following arguments is required: -u/--url, -f/--file, -z/--zone, -c/--check")

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
        for file_path in args.zone:
            domains_from_zone_file = extract_domains_from_zone_file(file_path, all_domains)

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
        logging.info(f"Domains have been saved to {args.output}")
    else:
        logging.info("No domains found.")

    if unique_resolved_domains:
        logging.info(f"Resolved domains from IP addresses have been saved to resolved.txt")
    else:
        logging.info("No resolved domains from IP addresses.")

    if args.check:
        check_file = args.check if args.check is not True else args.output
        output_file = os.path.splitext(args.output)[0] + '_checked.txt'
        check_domains(check_file, output_file, max_workers=20)
        logging.info(f"Checked endpoints have been saved to {output_file}")

if __name__ == "__main__":
    print(BANNER)
    main()
