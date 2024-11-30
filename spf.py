import re
import dns.resolver
import dns.message
import dns.query
import ipaddress
from colorprint import *

################
# FUTURE WORK: #
########################################################################################################
# Handle multiple return paths
########################################################################################################

###############
# TODO/FIXES: #
########################################################################################################
# Handle softfail and neutral
########################################################################################################

def get_spf_records(domain):
    spf_records = []
    visited_domains = set()
    
    def fetch_spf(domain):
        if domain in visited_domains:
            return
        visited_domains.add(domain)
        
        query = dns.message.make_query(domain, 'TXT')
        try:
            response = dns.query.tcp(query, '1.1.1.1')
            for answer in response.answer:
                for txt_string in answer.items:
                    txt_record = txt_string.to_text().strip('"')
                    if "v=spf1" in txt_record:
                        spf_records.append(txt_record)
                    if "include:" in txt_record:
                        included_domain = txt_record.split("include:")[1].split()[0]
                        fetch_spf(included_domain)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            print(f"No SPF record found for domain: {domain}")
    
    fetch_spf(domain)
    return spf_records

def parse_spf_ips(spf_records):
    ip_ranges = []
    for spf in spf_records:
        for part in spf.split():
            if part.startswith('ip4:'):
                ip_ranges.append(part[4:])
            elif part.startswith('ip6:'):
                ip_ranges.append(part[4:])
    return ip_ranges

def extract_ip_from_received(received_header):
    try:
        from_clause = re.search(r'from\s+.*?\[(.*?)\]', received_header)
        if from_clause:
            ip_candidate = from_clause.group(1)
            if ipaddress.ip_address(ip_candidate):
                return ip_candidate
    except ValueError:
        pass
    return None

def is_ip_in_range(ip, range_string):
    try:
        ip_obj = ipaddress.ip_address(ip)
        range_obj = ipaddress.ip_network(range_string, strict=False)
        return ip_obj in range_obj
    except ValueError:
        return False

def verify_eml_spf(msg):
    print_centered_colored("########################################################################################################", Fore.MAGENTA)
    print_centered_colored("# SPF VERIFICATION #", Fore.LIGHTMAGENTA_EX)
    print_centered_colored("########################################################################################################", Fore.MAGENTA)
    
    from_header_domain = msg.get('From').split()[-1].strip('<>').split('@')[-1]
    return_path = msg.get('Return-Path')
    if return_path:
        email = return_path.strip('<>')
        return_path_domain = email.split('@')[-1]
        print(Fore.LIGHTBLUE_EX + "Domain from Return-Path:\n" + Style.RESET_ALL, return_path_domain)

        spf_records = get_spf_records(return_path_domain)
        print(Fore.LIGHTBLUE_EX + "\nSPF Records:\n" + Style.RESET_ALL, spf_records)
        
        ip_ranges = parse_spf_ips(spf_records)
        print(Fore.LIGHTBLUE_EX + "\nSPF IP Ranges:\n" + Style.RESET_ALL, ip_ranges)

        received_headers = msg.get_all('Received')
        if received_headers:
            spf_passed = False
            for index, received_header in enumerate(received_headers):
                print(Fore.LIGHTBLUE_EX + f"\nReceived Header [{index + 1}]:\n" + Style.RESET_ALL, received_header)
                
                sending_ip = extract_ip_from_received(received_header)
                if sending_ip:
                    print(Fore.LIGHTCYAN_EX + "\nSender's IP:\n" + Style.RESET_ALL, sending_ip)

                    for ip_range in ip_ranges:
                        if is_ip_in_range(sending_ip, ip_range):
                            print(Fore.LIGHTGREEN_EX + f"\n!! SPF Verification Passed !!\nMatch found: {sending_ip} is in range {ip_range}!\n" + Style.RESET_ALL)
                            spf_passed = True
                            break
                else:
                    print(Fore.LIGHTYELLOW_EX + f"\nNo valid IP found in Received header [{index + 1}]. Moving to the next..." + Style.RESET_ALL)
                
                if spf_passed:
                    break

            if not spf_passed:
                print(Fore.LIGHTRED_EX + f"!! SPF Verification Failed !!\nNo match found for any IP in SPF record." + Style.RESET_ALL)
        else:
            print(Fore.LIGHTRED_EX + "No Received headers found in the email." + Style.RESET_ALL)
    else:
        print(Fore.LIGHTRED_EX + "Return-Path header not found." + Style.RESET_ALL)

    return spf_passed, from_header_domain, return_path_domain