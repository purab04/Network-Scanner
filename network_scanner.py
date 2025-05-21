import scapy.all as scapy
import threading
import socket
from queue import Queue
import ipaddress

# Thread-safe queue for IPs to scan
ip_queue = Queue()
# Thread-safe list to store results
results = []

def get_mac(ip):
    """Send ARP request to get MAC address of IP."""
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def get_hostname(ip):
    """Try to resolve hostname for the IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def scan_ip():
    while not ip_queue.empty():
        ip = ip_queue.get()
        mac = get_mac(ip)
        if mac:
            hostname = get_hostname(ip)
            results.append({"IP": ip, "MAC": mac, "Hostname": hostname})
        ip_queue.task_done()

def main():
    # Input network in CIDR format
    network = input("Enter network (CIDR format, e.g. 192.168.1.0/24): ")

    # Generate all IPs in the network, excluding network & broadcast
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        print("Invalid network format")
        return

    all_hosts = list(net.hosts())
    print(f"Scanning {len(all_hosts)} hosts...")

    # Fill queue with IP addresses to scan
    for ip in all_hosts:
        ip_queue.put(str(ip))

    # Create threads
    thread_count = 50  # You can adjust this number
    threads = []

    for _ in range(thread_count):
        thread = threading.Thread(target=scan_ip)
        thread.daemon = True
        thread.start()
        threads.append(thread)

    # Wait for all threads to finish
    ip_queue.join()

    # Print results
    print("\nScan Results:")
    print(f"{'IP Address':<15} {'MAC Address':<18} {'Hostname'}")
    print("-" * 50)
    for device in results:
        print(f"{device['IP']:<15} {device['MAC']:<18} {device['Hostname']}")

if __name__ == "__main__":
    main()
