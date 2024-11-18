import scapy.all as scapy
import threading
import requests
import time

# Function to display ASCII art from a file
def display_ascii_art():
    try:
        with open("art.txt", "r") as file:
            art = file.read()
            print(art)
    except FileNotFoundError:
        print("ASCII art file 'art.txt' not found.")
    except Exception as e:
        print(f"Error reading ASCII art file: {e}")

# Function to get manufacturer from MAC address using MAC Vendors API
def get_manufacturer_from_mac(mac_address):
    url = f"https://api.macvendors.com/{mac_address}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.text.strip()  # The API returns the manufacturer name
        else:
            return "Unknown"  # Return Unknown if the API call fails or no manufacturer found
    except requests.RequestException as e:
        print(f"Error fetching manufacturer for {mac_address}: {e}")
        return "Unknown"  # Return Unknown if an error occurs

# Function to perform a network scan (ARP request) to discover devices in the local network
def scan_devices_continuously(network, devices, stop_event):
    print("\nStarting continuous device scanning... Press 'Enter' to stop the scan.")
    while not stop_event.is_set():
        arp_request = scapy.ARP(pdst=network)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        # Send ARP requests with a timeout of 3 seconds
        answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]

        for element in answered_list:
            ip_address = element[1].psrc
            mac_address = element[1].hwsrc
            manufacturer = get_manufacturer_from_mac(mac_address)

            # Check if the device already exists in the list, if not add it
            existing_device = next((device for device in devices if device["mac"] == mac_address), None)
            if existing_device is None:
                print(f"Found Device - IP: {ip_address} | MAC: {mac_address} | Manufacturer: {manufacturer}")
                devices.append({
                    "ip": ip_address,
                    "mac": mac_address,
                    "manufacturer": manufacturer
                })

        time.sleep(1)  # Wait for a second before scanning again

# Function to display the devices found in the network scan
def display_devices(devices):
    if not devices:
        print("No devices found.")
        return
    print("\nDevices found on the network:")
    for index, device in enumerate(devices, start=1):
        print(f"{index}. IP: {device['ip']} | MAC: {device['mac']} | Manufacturer: {device['manufacturer']}")

# Callback function to process each packet during sniffing
def packet_callback(packet):
    print("\nPacket Captured:")

    # Check if the packet has an IP layer
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")
        
        # Check if the packet has a TCP/UDP layer
        if packet.haslayer(scapy.TCP):
            print(f"Layer: TCP")
            print(f"Source Port: {packet[scapy.TCP].sport}")
            print(f"Destination Port: {packet[scapy.TCP].dport}")
        elif packet.haslayer(scapy.UDP):
            print(f"Layer: UDP")
            print(f"Source Port: {packet[scapy.UDP].sport}")
            print(f"Destination Port: {packet[scapy.UDP].dport}")
    
    # Check for ARP packets
    elif packet.haslayer(scapy.ARP):
        print("Layer: ARP")
        print(f"ARP Request: {packet[scapy.ARP].hwsrc} -> {packet[scapy.ARP].hwdst}")

    print(f"Packet Length: {len(packet)} bytes")

# Function to start sniffing on the selected device's IP address
def start_sniffing(device_ip, interface=None):
    print(f"\nSniffing packets from device {device_ip}...")

    # Ensure we are sniffing on the correct interface (optional)
    if interface:
        print(f"Sniffing on interface: {interface}")
        scapy.sniff(filter=f"ip host {device_ip}", store=False, prn=packet_callback, iface=interface)
    else:
        # Default to sniffing on all interfaces if none is specified
        scapy.sniff(filter=f"ip host {device_ip}", store=False, prn=packet_callback)

# Function to get the available network interfaces
def list_network_interfaces():
    interfaces = scapy.get_if_list()
    print("\nAvailable Network Interfaces:")
    for idx, iface in enumerate(interfaces, start=1):
        print(f"{idx}. {iface}")
    return interfaces

# Main menu function to interact with the user
def main_menu():
    devices = []  # List of devices found during the scan
    stop_event = threading.Event()  # Event to stop the scanning thread
    scan_thread = None  # Thread for continuous scanning
    sniff_thread = None  # Thread for sniffing packets
    
    while True:
        # Display the ASCII art above the menu
        display_ascii_art()

        print("\nNetwork Analyzer Menu:")
        print("1. Start scanning the entire network")
        print("2. Scan a specific IP range")
        print("3. Select device to sniff packets")
        print("4. Display found devices")
        print("5. Exit")
        choice = input("Please enter your choice (1/2/3/4/5): ")

        if choice == '1':
            # Start continuous scanning for the entire network (default to 192.168.1.0/24)
            if scan_thread is None or not scan_thread.is_alive():
                network = "192.168.1.0/24"  # Default network range
                print(f"Scanning the entire network: {network}")
                stop_event.clear()  # Reset stop event before starting the thread
                scan_thread = threading.Thread(target=scan_devices_continuously, args=(network, devices, stop_event))
                scan_thread.start()
                print("Scanning started. Press 'Enter' to stop scanning.")
            else:
                print("Scanning is already running.")

        elif choice == '2':
            # Scan a specific IP range
            if scan_thread is None or not scan_thread.is_alive():
                start_ip = input("Enter the start IP (e.g., 192.168.1.10): ")
                end_ip = input("Enter the end IP (e.g., 192.168.1.50): ")
                stop_event.clear()  # Reset stop event before starting the thread
                scan_thread = threading.Thread(target=scan_devices_continuously, args=(f"{start_ip}-{end_ip}", devices, stop_event))
                scan_thread.start()
                print("Scanning started. Press 'Enter' to stop scanning.")
            else:
                print("Scanning is already running.")

        elif choice == '3':
            # Select device and start sniffing
            if not devices:
                print("\nNo devices found. Please start scanning first.")
                continue

            device_choice = int(input("\nEnter the device number to select: "))
            if 1 <= device_choice <= len(devices):
                selected_device = devices[device_choice - 1]
                print(f"Selected device: IP = {selected_device['ip']} | MAC = {selected_device['mac']} | Manufacturer = {selected_device['manufacturer']}")
                
                # Choose interface for sniffing (optional)
                interfaces = list_network_interfaces()
                interface_choice = int(input(f"Choose the interface to sniff on (1-{len(interfaces)}): "))
                selected_iface = interfaces[interface_choice - 1]
                
                sniff_thread = threading.Thread(target=start_sniffing, args=(selected_device['ip'], selected_iface))
                sniff_thread.start()
                print("Packet sniffing started.")
            else:
                print("Invalid selection. Please try again.")

        elif choice == '4':
            # Display the list of devices found
            display_devices(devices)

        elif choice == '5':
            # Stop the scanning thread and exit
            print("Exiting Network Analyzer...")
            stop_event.set()  # Stop the continuous scanning
            if scan_thread is not None and scan_thread.is_alive():
                scan_thread.join()  # Wait for the thread to finish before exiting
            break

        else:
            print("Invalid choice. Please try again.")

# Run the menu system
if __name__ == "__main__":
    main_menu()
