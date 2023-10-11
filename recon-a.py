## RECON-A - an OSINT reconnaissance tool
## created by PhoenixMGA on sept 29 2023

import dns.resolver
import requests
import socket
import nmap
import dns
import pathlib
from concurrent.futures import ThreadPoolExecutor
from typing import Iterator
import pprint
import subprocess
import csv

def get_list_of_tlds():
    tlds_path = pathlib.Path("./SecLists-master/Discovery/DNS/tlds.txt")
    return get_lines_in_file(tlds_path)


def get_list_of_subdomains() -> list[str]:
    subdomains_file = pathlib.Path("./SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt")
    return get_lines_in_file(subdomains_file)


def get_lines_in_file(input_file: pathlib.Path) -> list[str]:
    file_content = input_file.read_text()
    return file_content.splitlines()


def get_ip_address(domain_name):
    ip_address = socket.gethostbyname(domain_name)
    return ip_address

def domain_name_exists(domain_name: str) -> bool:
    try:
        get_ip_address(domain_name)
        return True
    except (socket.gaierror, UnicodeError):
        return False
    
def parralel_filtering_of_domains(list_of_domains: list[str]) -> Iterator[str]:
    domain_names_exist_list = ThreadPoolExecutor(10).map(domain_name_exists, list_of_domains)

    for domain_name, exists in zip(list_of_domains, domain_names_exist_list):
        if exists:
            yield domain_name


def get_all_domains_names_that_exist() -> Iterator[str]:
    company_name = input("Enter the company name: ")
    extension_list = get_list_of_tlds()
    domain_names = [company_name + extension for extension in extension_list]

    return parralel_filtering_of_domains(domain_names)


def get_all_dns_reccords(domain_name: str) -> Iterator[tuple[str, str]]:
    list_of_reccord_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']

    for record_type in list_of_reccord_types:
        try:
            answers = dns.resolver.resolve(domain_name, record_type)
        except dns.resolver.NoAnswer:
            pass
        for answer in answers:
            yield record_type, answer


def search_ripe_database(domain: str):
    api_url = "https://rest.db.ripe.net/search.json"
    response = requests.get(api_url, params={"query-string": domain})
    ripe_database = response.json()
    pprint.pprint(ripe_database)


def try_most_common_ports(ip_address):
    most_common_ports = [20, 21, 22, 25, 53, 80, 123, 179,  443, 500, 587, 3389]
    most_common_ports_str = [str(x) for x in most_common_ports]
    comma_delimited_list = ",".join(most_common_ports_str)
    arguments = "-p " + comma_delimited_list
    nm = nmap.PortScanner()
    scan_result = nm.scan(str(ip_address), arguments=arguments)["scan"]
    for ip_address, scan_result_for_ip_address in scan_result.items():
        for protocol in ["tcp", "udp"]:
            for port_number in most_common_ports:
                if protocol in scan_result_for_ip_address:
                    if scan_result_for_ip_address[protocol][port_number]["state"] == "open":
                        yield port_number    


def screenshot_this_url(url: str):
    print("screeshoting", url)
    subprocess.run(["wkhtmltoimage", "https://" + url, f"./screenshots/{url}.png"])


def main():
    pool_to_make_screenshots = ThreadPoolExecutor(20)

    with open('output.csv', 'w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=['fqdn', 'ip_address',"record_type" ,'open_ports'])
        writer.writeheader()


        for domain in get_all_domains_names_that_exist():
            subdomains_to_try = [subdomain + "." + domain for subdomain in get_list_of_subdomains()]
            for subdomain in parralel_filtering_of_domains(subdomains_to_try):
                pool_to_make_screenshots.submit(screenshot_this_url, subdomain)
                for record_type, ip_address in get_all_dns_reccords(subdomain):
                    open_ports = try_most_common_ports(subdomain)
                    open_ports_str = [str(x) for x in open_ports]
                    dict_to_write = {"fqdn": subdomain, "ip_address": ip_address, "record_type": record_type, "open_ports": ";".join(open_ports_str)}
                    print(*dict_to_write.values())
                    writer.writerow(dict_to_write)
                search_ripe_database(domain)

    
    pool_to_make_screenshots.join()


main()
