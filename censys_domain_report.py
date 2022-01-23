#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from cgitb import lookup
from urllib import request
import requests
import json
import socket
import base64
import argparse
import dns.resolver
import sys
from censys.search import CensysHosts
from censys.common.config import get_config




class IP_Address(object):
    def __init__(self, IP, data):
        self.IP = IP
        self.data = {}

#Set global Censys lib
host_search = CensysHosts()


def search_subdomains(domain,basic_auth):
    # Do a search for potential subdomains using the parsed.names field of the certificate datebase. This seems to be impossible using the python API so we will need to use requests for this. Return interesting certificate data.

    url = "https://search.censys.io/api/v1/search/certificates"
    payload = json.dumps({
    "query": f"parsed.names: {domain}",
    "page": 1,
    "fields": [
        "parsed.names",
        "parsed.extensions.issuer_alt_name",
        "parsed.extensions.name_constraints.permitted_directory_names.email_address",
        "parsed.extensions.name_constraints.permitted_directory_names.domain_component",
        "parsed.fingerprint_sha256",
        "parsed.fingerprint_md5",
        "parsed.issuer"
    ],
    "flatten": False
    })
    headers = {
    'accept': 'application/json',
    'Authorization': f'Basic {basic_auth}',
    'Content-Type': 'application/json'
    }

    try:
        response = requests.request("POST", url, headers=headers, data=payload)
        response = json.loads(response.text)
    except requests.exceptions.HTTPError as err:
        sys.stderr.write('[!] Could not reach Censys')
        exit(1)

    list_of_probable_subdomains = []
    for result in response['results']:
        if result['parsed']['names'][0].endswith(domain):
            list_of_probable_subdomains.append(result)
            #print(f"[+] Possible subdomain found: {result['parsed']['names'][0]}")


    possible_subdomains = {
        "possible_subdomains" : list_of_probable_subdomains
    }

    return possible_subdomains


def interrogate_ip(ip_address):
    try:
        query = host_search.view(ip_address)
        return query
    except censys.base.CensysUnauthorizedException:
        sys.stderr.write("[!] Censys API Secret and ID not set! Run 'censys config' to configure.\n")
        exit(1)
    except censys.base.CensysRateLimitExceededException:
        sys.stderr.write("[!] Censys API account search limit reached!\n")
        exit(1)
    except censys.base.CensysException as e:
        # catch the Censys Base exception, example "only 1000 first results are available"
        sys.stderr.write("[!] Something bad happened, " + repr(e))
        exit(1)

def lookup_domain_ip(domain):
    try: 
        ip_addrs = list( map( lambda x: x[4][0], socket.getaddrinfo( \
        domain,22,type=socket.SOCK_STREAM)))
        return ip_addrs
    except Exception as e:
        print(f'[!] Could not resolve IP for {domain} - {e}')
        raise SystemExit()

def lookup_txt_records(domain):   
    txt_records_raw = dns.resolver.resolve(domain, 'TXT')
    if txt_records_raw:
        txt_records = []
        for item in txt_records_raw:
            txt_records.append(item.to_text())
        return txt_records
    else:
        print(f'[-] No TXT records found for {domain}')


def main():

    parser = argparse.ArgumentParser("arguments")
    parser.add_argument("-d","--domain", help="domain you wish to search for", required=True)
    parser.add_argument("-o","--outfile", help="filename to put results in. default is outfile.json", default="outfile.json")
    args = parser.parse_args()
    print(f'[#] Searching for {args.domain} ...')


    # Get configured creds for basic auth api calls 
    try:
        config = get_config()
        api_id=config.get('DEFAULT','api_id')
        api_secret=config.get('DEFAULT','api_secret')
        basic_auth = f'{api_id}:{api_secret}'
        basic_auth = basic_auth.encode('ascii')
        basic_auth = base64.b64encode(basic_auth)
        basic_auth = basic_auth.decode('ascii')
    except Exception as E:
        sys.stderr.write("[!] Censys API Secret and ID not set! Run 'censys config' to configure.")

    #build a dict to store results in
    global_results = {
        args.domain: {
            "IP Addresses":[],
            "TXT Records":[],
        }
    }

    #Get TXT records for the domain. These can sometimes point to technologies accociated with the domain. This wont get all of them but it will be a good place to start
    txt_records = lookup_txt_records(args.domain)
    print("[!] Found the following TXT records: ")
    for record in txt_records:
        print(f"[+] {record}")
    global_results[args.domain]["TXT Records"] = txt_records

    # Get IPs accociated with the target
    target_ips=lookup_domain_ip(args.domain)
    print("[!] Found the following IPs: ", end='')
    print(*target_ips, sep=', ')
    global_results[args.domain]["IP Addresses"] = dict.fromkeys(target_ips, {})

    #Lookup IPs and add them to the dict
    for ip in global_results[args.domain]["IP Addresses"].keys():
        print(f"[#] Searching for data on {ip}")
        ip_results = interrogate_ip(ip)
        global_results[args.domain]["IP Addresses"][ip] = ip_results

        if 'names' in ip_results['dns'] and len(ip_results['dns']['names']) > 10 and sum(args.domain in name_search for name_search in ip_results['dns']['names']) < 5:
            print(f"[{ip}] [!] Likely domain is on a shared host")

        #Print some useful information from the search to the user in the Terminal 
        for service in ip_results['services']:
            service_name = service['service_name']
            service_port = service['port']
            print(f"[{ip}] [!] Service {service_name} on port: {service_port}")
            if 'jarm' in service:
                jarm = service['jarm']['fingerprint']
                print(f"[{ip}] [+] Attribute of interest: JARM fingerprint: {jarm}")
            if 'http' in service and service['http']['response']['headers']['Server']:   
                server_id = service['http']['response']['headers']['Server']
                print(f"[{ip}] [+] Attribute of interest: Server info: {server_id}")
        if ip_results['location']:
            print(f"[{ip}] [+] Possible location:")
            for key, value in ip_results['location'].items():
                print(f'[{ip}] [+]  {key}: {value}')

    #Get a list of possible subdomains by mention of the domain name in certificate records 
    print(f"[#] Searching for potential subdomains ...")
    possible_subdomains = search_subdomains(args.domain,basic_auth)

    #Make a nice human readable list for terminal outbut, although fingereprints are not identical we dont need to display things more than once to the user
    human_readable_list = []
    for subdomain in possible_subdomains["possible_subdomains"]:
        human_readable_list.append(subdomain['parsed']['names'][0])
    humanreadable_list = set(human_readable_list)
    for subdomain_hr in humanreadable_list:
        if not subdomain_hr == args.domain:
            print(f"[+] Possible subdomain found: {subdomain_hr}")
    
    global_results[args.domain]["Possible Subdomains"] = possible_subdomains

    # Print the output of the report to a file
    print(f"[#] Saving report to {args.outfile}")
    file_out = open(args.outfile, "w")
    file_out.write(json.dumps(global_results))
    file_out.close()



    print(f"[$] Done! Quitting.")
    exit(1)

if __name__ == "__main__":
    main()



