import requests
import json

"""
检测ip地址是否恶意
"""

ip_add = input("Enter IP address: ")
api = "<api-key>"
url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_add}/analyse"

headers = {
    "accept": "application/json",
    "x-apikey": api
}

# send scan request
response = requests.post(url, headers=headers)
res_dict = json.loads(response.text)
report_url = res_dict['data']['links']['self']
# get report
report_result = requests.get(report_url, headers=headers)
report_result_dict = json.loads(report_result.text)
result = report_result_dict['data']['attributes']['stats']
print("Malicious: ", result['malicious'])
print("Suspicious: ", result['suspicious'])
print("Undetected: ", result['undetected'])
print("Harmless: ", result['harmless'])
