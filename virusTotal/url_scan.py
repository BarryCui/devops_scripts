import requests
import json

"""
检测URL是否恶意
"""

api_url = "https://www.virustotal.com/api/v3/urls"
scan_url = input("Enter URL: ")
api = "<api-key>"

payload = { "url": scan_url }
headers = {
    "accept": "application/json",
    "x-apikey": api,
    "content-type": "application/x-www-form-urlencoded"
}
# send scan request
response = requests.post(api_url, data=payload, headers=headers)
res_dict = json.loads(response.text)
report_url = res_dict['data']['links']['self']
# get scan report
report_response = requests.get(report_url, headers=headers)
report_res_dict = json.loads(report_response.text)
report_result = report_res_dict['data']['attributes']['stats']
print("Malicious: ", report_result['malicious'])
print("Suspicious: ", report_result['suspicious'])
print("Undetected: ", report_result['undetected'])
print("Harmless: ", report_result['harmless'])
