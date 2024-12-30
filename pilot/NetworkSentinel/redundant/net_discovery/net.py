import scapy.all as scapy
import threading
import requests
import time
import logging
import ipaddress
import json
import os
from datetime import datetime
from collections import defaultdict
import signal
import sys
from typing import Dict, List, Optional, Set

class NetworkAnalyzer:
    def __init__(self):
        self.devices = []  # List of currently detected devices
        self.device_history = defaultdict(list)  # Track device appearance history
        self.mac_vendor_cache = {}  # Cache for MAC vendor lookups
        self.stop_event = threading.Event()
        self.active_threads = set()  # Track all active threads
        self.packet_filters = set()  # Custom packet filters
        self.setup_logging()
        self.setup_signal_handlers()
        
    def setup_logging(self):
        """Configure logging for the application"""
        log_dir = "logs"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        log_file = os.path.join(log_dir, f"network_analyzer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
    def setup_signal_handlers(self):
        """Set up handlers for graceful shutdown"""
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logging.info("Shutdown signal received. Cleaning up...")
        self.cleanup()
        sys.exit(0)
        
    def cleanup(self):
        """Perform cleanup operations"""
        self.stop_event.set()
        for thread in self.active_threads:
            if thread.is_alive():
                thread.join(timeout=1.0)
        self.save_device_history()
        
    def save_device_history(self):
        """Save device history to a JSON file"""
        history_file = "device_history.json"
        try:
            with open(history_file, 'w') as f:
                json.dump(self.device_history, f, indent=4, default=str)
            logging.info(f"Device history saved to {history_file}")
        except Exception as e:
            logging.error(f"Error saving device history: {e}")
            
    def get_manufacturer_from_mac(self, mac_address: str) -> str:
        """Get manufacturer name from MAC address with caching"""
        if mac_address in self.mac_vendor_cache:
            return self.mac_vendor_cache[mac_address]
            
        url = f"https://api.macvendors.com/{mac_address}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                manufacturer = response.text.strip()
                self.mac_vendor_cache[mac_address] = manufacturer
                return manufacturer
        except requests.RequestException as e:
            logging.error(f"Error fetching manufacturer for {mac_address}: {e}")
        return "Unknown"
        
    def validate_ip_range(self, start_ip: str, end_ip: str) -> bool:
        """Validate IP range input"""
        try:
            start = ipaddress.ip_address(start_ip)
            end = ipaddress.ip_address(end_ip)
            return start <= end
        except ValueError:
            return False
            
    def scan_devices_continuously(self, network: str):
        """Continuously scan network for devices"""
        thread = threading.current_thread()
        self.active_threads.add(thread)
        
        try:
            while not self.stop_event.is_set():
                arp_request = scapy.ARP(pdst=network)
                broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast/arp_request
                
                answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
                
                current_time = datetime.now()
                for element in answered_list:
                    ip_address = element[1].psrc
                    mac_address = element[1].hwsrc
                    manufacturer = self.get_manufacturer_from_mac(mac_address)
                    
                    device_info = {
                        "ip": ip_address,
                        "mac": mac_address,
                        "manufacturer": manufacturer,
                        "last_seen": current_time
                    }
                    
                    # Update current devices list
                    existing_device = next((d for d in self.devices if d["mac"] == mac_address), None)
                    if existing_device is None:
                        self.devices.append(device_info)
                        logging.info(f"New device found - IP: {ip_address} | MAC: {mac_address} | Manufacturer: {manufacturer}")
                    else:
                        existing_device.update(device_info)
                    
                    # Update device history
                    self.device_history[mac_address].append({
                        "timestamp": current_time,
                        "ip": ip_address
                    })
                
                time.sleep(1)
        except Exception as e:
            logging.error(f"Error in scanning thread: {e}")
        finally:
            self.active_threads.remove(thread)
            
    def start_device_capture(self):
        """Start packet capture for a selected device"""
        if not self.devices:
            print("\nNo devices found. Please run a scan first.")
            return

        self.display_devices()
        try:
            device_choice = int(input("\nEnter device number to capture: ").strip())
            if not 1 <= device_choice <= len(self.devices):
                print("Invalid device selection.")
                return

            selected_device = self.devices[device_choice - 1]
            interfaces = self.list_network_interfaces()
            
            if not interfaces:
                print("No network interfaces available.")
                return

            interface_choice = int(input(f"\nChoose interface (1-{len(interfaces)}): ").strip())
            if not 1 <= interface_choice <= len(interfaces):
                print("Invalid interface selection.")
                return

            selected_iface = interfaces[interface_choice - 1]
            
            # Configure capture options
            print("\nCapture Options:")
            print("1. Capture all packets")
            print("2. TCP only")
            print("3. UDP only")
            print("4. Custom port")
            
            filter_choice = input("Select option (1-4): ").strip()
            filter_str = f"host {selected_device['ip']}"
            
            if filter_choice == '2':
                filter_str += " and tcp"
            elif filter_choice == '3':
                filter_str += " and udp"
            elif filter_choice == '4':
                try:
                    port = int(input("Enter port number: ").strip())
                    filter_str += f" and port {port}"
                except ValueError:
                    print("Invalid port number.")
                    return

            # Start capture in a new thread
            capture_thread = threading.Thread(
                target=self.start_capture,
                args=(selected_device['ip'], selected_iface, filter_str)
            )
            capture_thread.start()
            
            print(f"\nCapture started for {selected_device['ip']} on {selected_iface}")
            print("Packets will be saved to 'captured_packets.pcap'")
            print("Press Enter to stop capture...")
            input()
            self.stop_event.set()
            
        except ValueError:
            print("Invalid input. Please enter a number.")

    def start_capture(self, target_ip: str, interface: str, filter_str: str):
        """Handle packet capture with pcap writing"""
        thread = threading.current_thread()
        self.active_threads.add(thread)
        
        try:
            # Initialize counters for statistics
            self.packet_stats = {
                'total': 0,
                'tcp': 0,
                'udp': 0,
                'icmp': 0,
                'other': 0
            }
            
            def packet_handler(packet):
                """Handle each captured packet"""
                if self.stop_event.is_set():
                    return True
                
                # Update statistics
                self.packet_stats['total'] += 1
                if packet.haslayer(scapy.TCP):
                    self.packet_stats['tcp'] += 1
                elif packet.haslayer(scapy.UDP):
                    self.packet_stats['udp'] += 1
                elif packet.haslayer(scapy.ICMP):
                    self.packet_stats['icmp'] += 1
                else:
                    self.packet_stats['other'] += 1
                
                # Write packet to pcap file
                scapy.wrpcap('captured_packets.pcap', packet, append=True)
                
                # Display real-time statistics every 10 packets
                if self.packet_stats['total'] % 10 == 0:
                    self.display_capture_stats()
                
                return self.stop_event.is_set()

            # Start the capture
            scapy.sniff(
                filter=filter_str,
                iface=interface,
                prn=packet_handler,
                store=False
            )
            
        except Exception as e:
            logging.error(f"Error in capture thread: {e}")
        finally:
            self.active_threads.remove(thread)
            self.display_capture_stats()
            print("\nCapture stopped.")

    def display_capture_stats(self):
        """Display current capture statistics"""
        os.system('cls' if os.name == 'nt' else 'clear')
        print("\n=== Capture Statistics ===")
        print(f"Total Packets: {self.packet_stats['total']}")
        print(f"TCP Packets: {self.packet_stats['tcp']}")
        print(f"UDP Packets: {self.packet_stats['udp']}")
        print(f"ICMP Packets: {self.packet_stats['icmp']}")
        print(f"Other Packets: {self.packet_stats['other']}")
        print("=" * 25)

    def start_network_capture(self):
        """Start packet capture for all network traffic"""
        interfaces = self.list_network_interfaces()
        
        if not interfaces:
            print("No network interfaces available.")
            return

        try:
            interface_choice = int(input(f"\nChoose interface (1-{len(interfaces)}): ").strip())
            if not 1 <= interface_choice <= len(interfaces):
                print("Invalid interface selection.")
                return

            selected_iface = interfaces[interface_choice - 1]
            
            # Start capture with no IP filter
            capture_thread = threading.Thread(
                target=self.start_capture,
                args=('0.0.0.0', selected_iface, '')
            )
            capture_thread.start()
            
            print(f"\nCapture started on {selected_iface}")
            print("Packets will be saved to 'captured_packets.pcap'")
            print("Press Enter to stop capture...")
            input()
            self.stop_event.set()
            
        except ValueError:
            print("Invalid input. Please enter a number.")

    def packet_callback(self, packet):
        """Enhanced packet analysis callback"""
        try:
            timestamp = datetime.now()
            packet_info = {
                "timestamp": timestamp,
                "length": len(packet),
                "layers": []
            }
            
            # Analyze different packet layers
            if packet.haslayer(scapy.IP):
                ip_layer = packet[scapy.IP]
                packet_info["layers"].append({
                    "type": "IP",
                    "source": ip_layer.src,
                    "destination": ip_layer.dst,
                    "protocol": ip_layer.proto
                })
                
                # TCP analysis
                if packet.haslayer(scapy.TCP):
                    tcp_layer = packet[scapy.TCP]
                    packet_info["layers"].append({
                        "type": "TCP",
                        "sport": tcp_layer.sport,
                        "dport": tcp_layer.dport,
                        "flags": tcp_layer.flags
                    })
                    
                # UDP analysis
                elif packet.haslayer(scapy.UDP):
                    udp_layer = packet[scapy.UDP]
                    packet_info["layers"].append({
                        "type": "UDP",
                        "sport": udp_layer.sport,
                        "dport": udp_layer.dport
                    })
                    
                # ICMP analysis
                elif packet.haslayer(scapy.ICMP):
                    icmp_layer = packet[scapy.ICMP]
                    packet_info["layers"].append({
                        "type": "ICMP",
                        "type_id": icmp_layer.type,
                        "code": icmp_layer.code
                    })
                    
            # ARP analysis
            elif packet.haslayer(scapy.ARP):
                arp_layer = packet[scapy.ARP]
                packet_info["layers"].append({
                    "type": "ARP",
                    "operation": "request" if arp_layer.op == 1 else "reply",
                    "source_mac": arp_layer.hwsrc,
                    "dest_mac": arp_layer.hwdst,
                    "source_ip": arp_layer.psrc,
                    "dest_ip": arp_layer.pdst
                })
                
            # Apply packet filters
            if self.should_display_packet(packet_info):
                self.display_packet_info(packet_info)
                
        except Exception as e:
            logging.error(f"Error in packet callback: {e}")
            
    def should_display_packet(self, packet_info: Dict) -> bool:
        """Check if packet matches current filters"""
        if not self.packet_filters:
            return True
            
        for filter_func in self.packet_filters:
            if filter_func(packet_info):
                return True
        return False
        
    def display_packet_info(self, packet_info: Dict):
        """Display formatted packet information"""
        print("\n=== Packet Captured ===")
        print(f"Timestamp: {packet_info['timestamp']}")
        print(f"Length: {packet_info['length']} bytes")
        
        for layer in packet_info['layers']:
            print(f"\nLayer: {layer['type']}")
            for key, value in layer.items():
                if key != 'type':
                    print(f"  {key}: {value}")
                    
    def start_sniffing(self, device_ip: str, interface: Optional[str] = None):
        """Start packet sniffing for a specific device"""
        thread = threading.current_thread()
        self.active_threads.add(thread)
        
        try:
            filter_str = f"ip host {device_ip}"
            if interface:
                scapy.sniff(
                    filter=filter_str,
                    store=False,
                    prn=self.packet_callback,
                    iface=interface,
                    stop_filter=lambda _: self.stop_event.is_set()
                )
            else:
                scapy.sniff(
                    filter=filter_str,
                    store=False,
                    prn=self.packet_callback,
                    stop_filter=lambda _: self.stop_event.is_set()
                )
        except Exception as e:
            logging.error(f"Error in sniffing thread: {e}")
        finally:
            self.active_threads.remove(thread)
            
    def list_network_interfaces(self) -> List[str]:
        """Get list of available network interfaces"""
        try:
            interfaces = scapy.get_if_list()
            print("\nAvailable Network Interfaces:")
            for idx, iface in enumerate(interfaces, start=1):
                print(f"{idx}. {iface}")
            return interfaces
        except Exception as e:
            logging.error(f"Error listing network interfaces: {e}")
            return []
            
    def add_packet_filter(self, filter_func):
        """Add a custom packet filter"""
        self.packet_filters.add(filter_func)
        
    def clear_packet_filters(self):
        """Clear all packet filters"""
        self.packet_filters.clear()
        
    def display_devices(self):
        """Display currently found devices"""
        if not self.devices:
            print("No devices found.")
            return
            
        print("\nDevices found on the network:")
        for index, device in enumerate(self.devices, start=1):
            last_seen = device.get('last_seen', 'Unknown')
            print(f"{index}. IP: {device['ip']} | MAC: {device['mac']} | "
                  f"Manufacturer: {device['manufacturer']} | Last seen: {last_seen}")
                  
    def display_menu_header(self):
        """Display menu header with current status"""
        os.system('cls' if os.name == 'nt' else 'clear')
        print("\n=== Network Analyzer Tool ===")
        print("Current Status:")
        print(f"Active Scans: {'Yes' if any(t.is_alive() for t in self.active_threads) else 'No'}")
        print(f"Devices Found: {len(self.devices)}")
        print(f"Packet Filters: {len(self.packet_filters)}")
        print("=" * 30)

    def scanning_menu(self):
        """Submenu for scanning operations"""
        while True:
            print("\nScanning Operations:")
            print("1. Quick Scan (Default Network)")
            print("2. Custom IP Range Scan")
            print("3. Stop All Scans")
            print("4. View Scan Results")
            print("5. Back to Main Menu")
            
            choice = input("\nEnter your choice (1-5): ").strip()
            
            if choice == '1':
                self.start_quick_scan()
            elif choice == '2':
                self.start_custom_scan()
            elif choice == '3':
                self.stop_all_scans()
            elif choice == '4':
                self.view_scan_results()
            elif choice == '5':
                break
            else:
                print("Invalid choice. Please try again.")

    def packet_capture_menu(self):
        """Submenu for packet capture operations"""
        while True:
            print("\nPacket Capture Operations:")
            print("1. Start Capture (Selected Device)")
            print("2. Start Capture (All Devices)")
            print("3. Configure Capture Filters")
            print("4. View Active Captures")
            print("5. Stop All Captures")
            print("6. Back to Main Menu")
            
            choice = input("\nEnter your choice (1-6): ").strip()
            
            if choice == '1':
                self.start_device_capture()
            elif choice == '2':
                self.start_network_capture()
            elif choice == '3':
                self.configure_capture_filters()
            elif choice == '4':
                self.view_active_captures()
            elif choice == '5':
                self.stop_all_captures()
            elif choice == '6':
                break
            else:
                print("Invalid choice. Please try again.")

    def main_menu(self):
        """Improved main menu system"""
        while True:
            self.display_menu_header()
            print("\nMain Menu:")
            print("1. Network Scanning")
            print("2. Packet Capture")
            print("3. Device Management")
            print("4. Analysis & Reports")
            print("5. Settings")
            print("6. Exit")
            
            choice = input("\nEnter your choice (1-6): ").strip()
            
            if choice == '1':
                self.scanning_menu()
            elif choice == '2':
                self.packet_capture_menu()
            elif choice == '3':
                self.device_management_menu()
            elif choice == '4':
                self.analysis_menu()
            elif choice == '5':
                self.settings_menu()
            elif choice == '6':
                print("Exiting Network Analyzer...")
                self.cleanup()
                break
            else:
                print("Invalid choice. Please try again.")

    def start_quick_scan(self):
        """Start a quick scan of the default network"""
        if not any(t.is_alive() for t in self.active_threads):
            network = "192.168.1.0/24"
            logging.info(f"Starting quick scan on {network}")
            self.stop_event.clear()
            scan_thread = threading.Thread(
                target=self.scan_devices_continuously,
                args=(network,)
            )
            scan_thread.start()
            print(f"\nQuick scan started on {network}")
            print("Press Enter to stop the scan...")
            input()
            self.stop_event.set()
        else:
            print("A scan is already running.")
                    
            elif choice == '2':
                if not any(t.is_alive() for t in self.active_threads):
                    start_ip = input("Enter the start IP (e.g., 192.168.1.10): ")
                    end_ip = input("Enter the end IP (e.g., 192.168.1.50): ")
                    
                    if self.validate_ip_range(start_ip, end_ip):
                        self.stop_event.clear()
                        scan_thread = threading.Thread(
                            target=self.scan_devices_continuously,
                            args=(f"{start_ip}-{end_ip}",)
                        )
                        scan_thread.start()
                    else:
                        print("Invalid IP range. Please try again.")
                else:
                    print("Scanning is already running.")
                    
            elif choice == '3':
                if not self.devices:
                    print("\nNo devices found. Please start scanning first.")
                    continue
                    
                self.display_devices()
                try:
                    device_choice = int(input("\nEnter the device number to select: "))
                    if 1 <= device_choice <= len(self.devices):
                        selected_device = self.devices[device_choice - 1]
                        interfaces = self.list_network_interfaces()
                        
                        if interfaces:
                            interface_choice = int(input(f"Choose the interface (1-{len(interfaces)}): "))
                            if 1 <= interface_choice <= len(interfaces):
                                selected_iface = interfaces[interface_choice - 1]
                                sniff_thread = threading.Thread(
                                    target=self.start_sniffing,
                                    args=(selected_device['ip'], selected_iface)
                                )
                                sniff_thread.start()
                                print("Packet sniffing started.")
                            else:
                                print("Invalid interface selection.")
                    else:
                        print("Invalid device selection.")
                except ValueError:
                    print("Invalid input. Please enter a number.")
                    
            elif choice == '4':
                self.display_devices()
                
            elif choice == '5':
                print("\nAvailable filter types:")
                print("1. TCP only")
                print("2. UDP only")
                print("3. ICMP only")
                print("4. Custom port")
                
                filter_choice = input("Select filter type (1-4): ").strip()
                
                if filter_choice == '1':
                    self.add_packet_filter(lambda packet: any(layer.get('type') == 'TCP' for layer in packet.get('layers', [])))
                    print("TCP packet filter added.")
                elif filter_choice == '2':
                    self.add_packet_filter(lambda packet: any(layer.get('type') == 'UDP' for layer in packet.get('layers', [])))
                    print("UDP packet filter added.")
                elif filter_choice == '3':
                    self.add_packet_filter(lambda packet: any(layer.get('type') == 'ICMP' for layer in packet.get('layers', [])))
                    print("ICMP packet filter added.")
                elif filter_choice == '4':
                    try:
                        port = int(input("Enter port number to filter: ").strip())
                        self.add_packet_filter(lambda packet: any(
                            (layer.get('type') in ('TCP', 'UDP') and 
                             (layer.get('sport') == port or layer.get('dport') == port))
                            for layer in packet.get('layers', [])
                        ))
                        print(f"Port {port} filter added.")
                    except ValueError:
                        print("Invalid port number.")
                else:
                    [print("Invalid filter choice.") for l in p['layers']]
                    print("TCP filter added.")
                elif filter_choice == '2':
                    self.add_packet_filter(lambda p: any(l['type'] == 'UDP' for l in p['layers']))
                    print("UDP filter added.")
                elif filter_choice == '3':
                    self.add_packet_filter(lambda p: any(l['type'] == 'ICMP' for l in p['layers']))
                    print("ICMP filter added.")
                elif filter_choice == '4':
                    try:
                        port = int(input("Enter port number to filter: "))
                        self.add_packet_filter(lambda p: any(
                            (l['type'] in ('TCP', 'UDP') and 
                             (l['sport'] == port or l['dport'] == port))
                            for l in p['layers']
                        ))
                        print(f"Port {port} filter added.")
                    except ValueError:
                        print("Invalid port number.")
                else:
                    print("Invalid filter choice.")
                    
            elif choice == '6':
                self.clear_packet_filters()
                print("All packet filters cleared.")
                
            elif choice == '7':
                if not self.device_history:
                    print("No device history available.")
                else:
                    print("\nDevice History:")
                    for mac, history in self.device_history.items():
                        manufacturer = self.get_manufacturer_from_mac(mac)
                        print(f"\nDevice: {mac} (Manufacturer: {manufacturer})")
                        for entry in history[-5:]:  # Show last 5 entries
                            print(f"  {entry['timestamp']}: IP = {entry['ip']}")
                            
            elif choice == '8':
                print("Exiting Network Analyzer...")
                self.cleanup()
                break
                
            else:
                print("Invalid choice. Please try again.")

def main():
    """Main entry point for the application"""
    try:
        analyzer = NetworkAnalyzer()
        analyzer.main_menu()
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()