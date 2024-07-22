import subprocess
import optparse
import re

# change interface mac address on linux

def change_mac(interface, mac):
    # change the interface mac address
    subprocess.call('sudo ifconfig ' + interface + ' down',shell=True)
    subprocess.call('sudo ifconfig ' + interface + ' hw ether ' + mac,shell=True)
    subprocess.call('sudo ifconfig ' + interface + ' up',shell=True)
    print('[+]  ' + interface + ' MAC address has been changed to ' + mac)

def get_args():
    # receive arguments from user inputs
    parser = optparse.OptionParser()
    parser.add_option("-i","--interface",dest="interface",help="choose a interface to change its MAC address")
    parser.add_option("-m","--mac",dest="mac",help="enter a new MAC address")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error('[-]  error: Please enter an interface')
    elif not options.mac:
        parser.error('[-]  error: Please enter a MAC address')
    return options    

def print_mac(interface):
    # print the current mac address
    ifconfig_output = subprocess.check_output(['ifconfig',interface],encoding='utf-8')
    search_output = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w",ifconfig_output)
    
    if search_output:
        print(f"Current MAC: " + search_output.group(0))
    else:
        print('[-]  MAC address for the interface not found!')

options = get_args()
change_mac(options.interface,options.mac)
print_mac(options.interface)
