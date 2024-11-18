#OSDEC using nmap

import nmap

def scan_network(network_range):
    # Initialize the PortScanner object
    nm = nmap.PortScanner()

    # Scan the provided network range for devices
    print(f"Scanning network: {network_range}")
    nm.scan(hosts=network_range, arguments='-O')  # '-O' flag enables OS detection

    devices = []
    
    for host in nm.all_hosts():
        if 'hostnames' in nm[host]:
            host_info = {
                'ip': host,
                'hostnames': nm[host].hostname(),
                'os': nm[host].get('osmatch', 'Unknown')
            }
            devices.append(host_info)
    
    return devices

def display_device_info(devices):
    print("\nDetected Devices and Their Operating Systems:")
    for device in devices:
        ip = device['ip']
        hostnames = device['hostnames'] if device['hostnames'] else 'N/A'
        os = device['os'][0] if device['os'] != 'Unknown' else 'OS detection failed'
        
        print(f"IP: {ip}")
        print(f"Hostnames: {hostnames}")
        print(f"Operating System: {os}")
        print('-' * 40)

if __name__ == "__main__":
    # Define the network range to scan (e.g., 192.168.1.0/24 for a local network)
    network_range = "192.168.1.0/24"

    # Scan the network and get the device info
    devices = scan_network(network_range)

    # Display the detected devices and their OS
    display_device_info(devices)
