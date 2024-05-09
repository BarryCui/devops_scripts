#!/bin/bash
# The script does web enumerations automatically. It does the following:
# 1. Find subdomains
# 2. Take screenshots for each working domains
# 3. Perform port scans for each working domains
# 4. Find web content and subdirectories(first layer) for each working domain
#
# Before use, install the tools below:
# subfinder, nmap, assetfinder, gowitness, dirb, seclists
#
# Usage example:
# sudo ./auto_enum.sh example.com
#
#
domain=$1
RED="\033[1;31m"
BLUE="\033[0;34m"
RESET="\033[0m"

subdomain_path=$domain/subdomains
screenshot_path=$domain/screenshots
portscan_path=$domain/portscans
# Replace the wordlist with your own one
dirb_wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt"
# Create folders
if [ ! -d "$domain" ]; then
    mkdir $domain
fi

if [ ! -d "$subdomain_path" ]; then
    mkdir $subdomain_path
fi

if [ ! -d "$screenshot_path" ]; then
    mkdir $screenshot_path
fi


if [ ! -d "$portscan_path" ]; then
    mkdir $portscan_path
fi
# Launch tools to do the work
echo -e "${RED} [+] Begin subdomain finding process... ${RESET}"

echo -e "${BLUE} [+] Launching subfinder ... ${RESET}"
subfinder -d $domain > $subdomain_path/found.txt

echo -e "${BLUE} [+] Launching assetfinder ... ${RESET}"
assetfinder $domain | grep $domain >> $subdomain_path/found.txt

echo -e "${BLUE} [+] Finding alive subdomains ... ${RESET}"
cat $subdomain_path/found.txt | grep $domain | sort -u | httprobe | sed 's/https:\/\///g; s/http:\/\///g' > $subdomain_path/alive.txt  

echo -e "${RED} [+] End subdomain finding process... ${RESET}"

echo -e "${RED} [+] Begin taking screenshot process... ${RESET}"

echo -e "${BLUE} [+] Launching gowitness ... ${RESET}"
gowitness file -f $subdomain_path/alive.txt -P $screenshot_path

echo -e "${RED} [+] End taking screenshot process... ${RESET}"

echo -e "${RED} [+] Begin port scanning process... ${RESET}"

echo -e "${BLUE} [+] Launching nmap... ${RESET}"
nmap -iL $subdomain_path/alive.txt -T4 -A -p21-23,80,389,443,445,1433,3306,3389 -oN $portscan_path/found.txt

echo -e "${RED} [+] End port scanning process... ${RESET}"

echo -e "${RED} [+] Begin fuzzing subdirectory process... ${RESET}"

echo -e "${BLUE} [+] Launching dirb... ${RESET}"

# Read file from alive.txt and fuzz each domain
while IFS= read -r domain; do
    # Replace . with _ to create filename
    safe_domain=$(echo "$domain" | tr '.' '_')

    # Dealing with each domain
    echo "Processing: $domain"

    # Execute dirb with HTTP
    dirb "http://$domain" $dirb_wordlist -o "$subdomain_path/http_$safe_domain.txt"

    # Execute dirb with HTTPS
    dirb "https://$domain" $dirb_wordlist -o "$subdomain_path/https_$safe_domain.txt"

    echo "Domain $domain done fuzzing."
done < "$subdomain_path/alive.txt"

echo -e "${RED} [+] End fuzzing subdirectory process... ${RESET}"
