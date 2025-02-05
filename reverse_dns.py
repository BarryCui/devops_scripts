import socket

ip_address = "8.8.8.8"
try:
    hostname = socket.gethostbyaddr(ip_address)
    print(f"Hostname for {ip_address} is: {hostname[0]}")
except socket.herror as e:
    print(f"Unable to resolve {ip_address}: {e}")
