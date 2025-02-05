import requests
import json

"""
检测域名是否恶意
"""
api = "<api-key>"
domain = input('Domain name: ')
url = f"https://www.virustotal.com/api/v3/domains/{domain}/analyse"

headers = {
    "accept": "application/json",
    "x-apikey": api
}

rescan_response = requests.post(url, headers=headers)
res_dict = json.loads(rescan_response.text)
result_url = res_dict['data']['links']['self']

url_response = requests.get(result_url, headers=headers)
url_res_dict = json.loads(url_response.text)
url_results = url_res_dict['data']['attributes']['stats']
print("Malicious: ", url_results['malicious'])
print("Suspicious: ", url_results['suspicious'])
print("Undetected: ", url_results['undetected'])
print("Harmless: ", url_results['harmless'])

