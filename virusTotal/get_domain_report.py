
import requests
import json

"""
Request rate 	4 lookups / min
Daily quota 	500 lookups / day
Monthly quota 	15.5 K lookups / month 

检测域名是否恶意，获取已检测的报告，并非新检测
"""

# virusTotal API key
api = "<api-key>"

domain = input("Domain name: ")

url = f"https://www.virustotal.com/api/v3/domains/{domain}"

headers = {
    "accept": "application/json",
    "x-apikey": api
}

response = requests.get(url, headers=headers)
res_dict = json.loads(response.text)
scan_results = res_dict['data']['attributes']['last_analysis_stats']
print("Malicious: ", scan_results['malicious'])
print("Suspicious: ", scan_results['suspicious'])
print("Undetected: ", scan_results['undetected'])
print("Harmless: ", scan_results['harmless'])
