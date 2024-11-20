import nmap

def scan_network(network_range):
    # Initialize the PortScanner object
    nm = nmap.PortScanner()

    # Scan the provided network range for devices with OS detection
    print(f"Scanning network: {network_range}")
    
    try:
        nm.scan(hosts=network_range, arguments='-O')  # '-O' flag enables OS detection
    except Exception as e:
        print(f"Error occurred during scan: {e}")
        return []

    devices = []
    
    for host in nm.all_hosts():
        host_info = {
            'ip': host,
            'hostnames': nm[host].hostname() if nm[host].hostname() else 'N/A',
            'os': extract_os_info(nm[host])
        }
        devices.append(host_info)
    
    return devices

def extract_os_info(host_data):
    # Try to extract the most likely OS match
    os_info = host_data.get('osmatch', [])
    if os_info:
        # Return the most probable OS
        return os_info[0]['name'] if isinstance(os_info[0], dict) else 'Unknown OS'
    else:
        return 'OS detection failed'

def display_device_info(devices):
    if not devices:
        print("No devices found or scan failed.")
        return

    print("\nDetected Devices and Their Operating Systems:")
    for device in devices:
        ip = device['ip']
        hostnames = device['hostnames']
        os = device['os']

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
