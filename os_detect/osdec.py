import subprocess
import socket
import os
from concurrent.futures import ThreadPoolExecutor

# Function to perform a ping sweep to find live hosts on a network
def ping_host(ip):
    """
    Perform a ping to check if the host is online
    """
    try:
        # For Linux/Mac
        # response = subprocess.run(['ping', '-c', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # For Windows
        response = subprocess.run(['ping', '-n', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if response.returncode == 0:
            return ip
    except Exception as e:
        return None

# Function to check open ports and try to grab a banner to determine the OS
def grab_banner(ip, port):
    """
    Attempt to grab a banner from a service on a specific port to identify the OS.
    """
    try:
        # Timeout of 2 seconds
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        s.send(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = s.recv(1024).decode('utf-8', errors='ignore')
        s.close()
        return banner
    except (socket.timeout, socket.error):
        return None

# Scan a range of IPs for live hosts
def scan_network(ip_range):
    live_hosts = []
    # Loop through all possible IP addresses in the range
    for i in range(1, 255):
        ip = f"{ip_range}.{i}"
        result = ping_host(ip)
        if result:
            live_hosts.append(ip)
            print(f"Host {ip} is online")
    return live_hosts

# Scan common ports to identify the OS by banner grabbing
def identify_os(ip):
    banners = {}
    common_ports = [80, 443, 21, 22, 23, 25, 110, 139, 445]  # Common ports (HTTP, FTP, SSH, etc.)

    for port in common_ports:
        banner = grab_banner(ip, port)
        if banner:
            banners[port] = banner
            print(f"Banner from {ip}:{port} - {banner}")
    
    # Simple checks based on banners (could be expanded with more complex logic)
    if any("Windows" in banner for banner in banners.values()):
        return "Windows"
    elif any("Linux" in banner for banner in banners.values()):
        return "Linux"
    elif any("Apache" in banner for banner in banners.values()):
        return "Linux (Apache Web Server)"
    elif any("nginx" in banner for banner in banners.values()):
        return "Linux (Nginx Web Server)"
    return "Unknown OS"

# Function to scan the network and try to detect the OS
def scan_and_identify_os(network_range):
    live_hosts = scan_network(network_range)
    os_info = {}
    
    # Use ThreadPoolExecutor to scan multiple hosts in parallel
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(identify_os, live_hosts)
    
    for ip, os in zip(live_hosts, results):
        os_info[ip] = os
        print(f"IP: {ip}, OS: {os}")
    
    return os_info

if __name__ == "__main__":
    # Define the network range (e.g., 192.168.1.0/24)
    network_range = "192.168.1"  # Last octet will range from 1 to 254

    # Scan the network and identify the OS of each device
    os_info = scan_and_identify_os(network_range)

    # Display the results
    print("\nFinal OS Information:")
    for ip, os in os_info.items():
        print(f"{ip}: {os}")
