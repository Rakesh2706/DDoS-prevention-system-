# DDoS-prevention-system-
import tkinter as tk
from tkinter import ttk
import time
from threading import Thread
from urllib.parse import urlparse
import socket
import scapy.all as scapy

# Configuration
MAX_REQUESTS_PER_IP = 10  # Max requests before blocking an IP
DDOS_DETECTION_THRESHOLD = 20  # Requests within a time window to trigger DDoS detection
TIME_WINDOW = 10  # Time window in seconds for counting requests

# In-memory request count and blacklist
request_counts = {}
blacklist = {}
monitored_websites = {}
domain_request_counts = {}  # To track requests per domain

# Function to reset state (reset tracking, no firewall rules for Windows)
def reset_state():
    global request_counts, blacklist, domain_request_counts
    request_counts = {}
    blacklist = {}
    domain_request_counts = {}
    update_log("State has been reset.")

# Function to capture traffic and count requests for specified websites
def capture_traffic(interface=None):
    # Automatically detect the interface if not provided
    if not interface:
        interface = scapy.conf.iface

    def process_packet(packet):
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src

            # Check if packet is a DNS query
            if packet.haslayer(scapy.DNS) and packet.haslayer(scapy.DNSQR):
                queried_domain = packet[scapy.DNSQR].qname.decode().rstrip('.').lower()  # Normalize domain

                # Track if it's in the list of monitored domains
                for domain in monitored_websites.keys():
                    if domain.lower() == queried_domain:
                        handle_request(ip_src, domain)
                        break

            # Check for requests to local server
            local_ip = get_local_ip(interface)
            if packet[scapy.IP].dst == local_ip:
                handle_request(ip_src, "Local Server")

    # Start sniffing packets on the given interface
    scapy.sniff(iface=interface, prn=process_packet, store=False)

def get_local_ip(interface):
    """Get the local IP address for the specified interface."""
    return scapy.get_if_addr(interface)

def handle_request(ip_src, domain):
    current_time = time.time()
    
    # Initialize request count per IP and domain
    if ip_src not in request_counts:
        request_counts[ip_src] = {}

    if domain not in request_counts[ip_src]:
        request_counts[ip_src][domain] = []

    # Append the current request time
    request_counts[ip_src][domain].append(current_time)

    # Update GUI with the new request data
    update_traffic_table(ip_src, domain, len(request_counts[ip_src][domain]))

    # Remove requests that are older than the time window
    request_counts[ip_src][domain] = [t for t in request_counts[ip_src][domain] if current_time - t <= TIME_WINDOW]

    # Check if the request count exceeds DDoS detection threshold
    if len(request_counts[ip_src][domain]) > DDOS_DETECTION_THRESHOLD:
        update_log(f"Potential DDoS attack detected on {domain} from {ip_src}!")
    else:
        update_log(f"Current requests to {domain}: {len(request_counts[ip_src][domain])}")

def add_monitored_website():
    website_url = website_entry.get()
    if website_url:
        # Parse the website URL and extract the hostname
        parsed_url = urlparse(website_url)
        domain = parsed_url.netloc or parsed_url.path  # Extract domain
        # Resolve domain to IP addresses using the socket module
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            monitored_websites[domain] = ips
            update_log(f"Monitoring added for: {domain} with IPs: {ips}")
            website_entry.delete(0, tk.END)
        except Exception as e:
            update_log(f"Error resolving domain {domain}: {e}")
            website_entry.delete(0, tk.END)

# Function to update the GUI traffic table
def update_traffic_table(ip, domain, request_count):
    for row in traffic_tree.get_children():
        if traffic_tree.item(row)["values"][0] == ip:
            traffic_tree.item(row, values=(ip, domain, request_count))
            return
    traffic_tree.insert("", tk.END, values=(ip, domain, request_count))

# Function to update the log area
def update_log(message):
    if 'log_text' in globals():  # Ensure log_text exists
        log_text.insert(tk.END, message + "\n")
        log_text.see(tk.END)

# Create GUI for real-time IP list and manual control
def create_gui():
    global website_entry, traffic_tree, log_text
    window = tk.Tk()
    window.title("DDoS Protection System Demo")

    # Entry to add websites to monitor
    website_label = tk.Label(window, text="Enter Website URL to Monitor:")
    website_label.pack()
    website_entry = tk.Entry(window)
    website_entry.pack()
    add_button = tk.Button(window, text="Add Website", command=add_monitored_website)
    add_button.pack()

    # Traffic table to display IPs and requests
    traffic_frame = tk.Frame(window)
    traffic_frame.pack(pady=10)

    traffic_tree = ttk.Treeview(traffic_frame, columns=("IP Address", "Domain", "Request Count"), show='headings')
    traffic_tree.heading("IP Address", text="IP Address")
    traffic_tree.heading("Domain", text="Domain")
    traffic_tree.heading("Request Count", text="Request Count")
    traffic_tree.pack()

    log_label = tk.Label(window, text="Event Log:")
    log_label.pack()

    # Log area to display events
    log_text = tk.Text(window, height=10, width=80)
    log_text.pack()

    window.mainloop()

# Start the capture and GUI in separate threads
if __name__ == "__main__":
    # Thread for packet capture
    capture_thread = Thread(target=capture_traffic, args=("Wi-Fi",), daemon=True)
    capture_thread.start()

    # Start the GUI
    create_gui()
