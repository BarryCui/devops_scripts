import dns.resolver
import socket

"""
输入主域名，基于子域名字典来查找可用的子域名
"""

# Translate IP to DNS
def reverseDns(ip):
    try:
        result = socket.gethostbyaddr(ip)
        return [result[0]] + result[1]  # Return the primary hostname and aliases
    except (socket.herror, socket.gaierror):
        return []  # Return an empty list if the IP cannot be resolved

# Translate DNS to IP
def dnsRequest(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')  # Resolve the domain to an IP address
        if result:
            print(f"Domain: {domain}")
            for answer in result:
                ip = answer.to_text()
                print(f"IP Address: {ip}")
                # Perform reverse DNS lookup on the IP address
                domain_names = reverseDns(ip)
                print(f"Domain Names: {domain_names}")
            print("----------------------------------------------------")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        #print(f"DNS resolution failed for: {domain}")
        return

# Look for subdomains
def subdomainSearch(domain, subdomains, nums):
    for subdomain in subdomains:
        full_domain = f"{subdomain}.{domain}"  # Construct the full subdomain
        dnsRequest(full_domain)  # Perform DNS resolution for the subdomain
        if nums:
            for i in range(0, 10):  # Append numbers to the subdomain
                numbered_domain = f"{subdomain}{i}.{domain}"
                dnsRequest(numbered_domain)

# Main script
if __name__ == "__main__":
    domain = input('Enter domain name:')
    subdomain_file = "subdomain.txt"
    
    try:
        with open(subdomain_file, "r") as f:
            subdomain_dic = f.read().splitlines()  # Read subdomains from the file
    except FileNotFoundError:
        print(f"Error: The file '{subdomain_file}' was not found.")
        exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        exit(1)

    subdomainSearch(domain, subdomain_dic, True)  # Start the subdomain search
