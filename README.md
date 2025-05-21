# Network Scanner Using Python

## By Inlighn Tech

---

## Objective

The objective of this project is to create a Python-based network scanner that detects active devices in a given IP range. This project helps understand network scanning, ARP requests, multi-threading, and socket programming in Python.

---

## Project Overview

Network scanning is an essential task for cybersecurity professionals to monitor active devices in a network. This project uses Python’s Scapy library to send ARP requests and retrieve the IP addresses, MAC addresses, and hostnames of connected devices. Multi-threading is implemented to speed up scanning in large networks.

---

## How the Project Works

1. **User Input:** User inputs a CIDR-based network address (e.g., `192.168.1.0/24`).
2. **IP Extraction:** The script generates all valid host IPs in the subnet.
3. **ARP Request:** Each IP is scanned using an ARP request.
4. **MAC Retrieval:** If a device responds, its MAC address is captured.
5. **Hostname Resolution:** The hostname is fetched via reverse DNS lookup.
6. **Multi-threading:** Multiple threads scan devices in parallel for efficiency.
7. **Results Display:** Found devices are listed with IP address, MAC address, and hostname.

---

## Features

- Uses ARP to detect active hosts on the network.
- Retrieves MAC addresses of discovered devices.
- Resolves hostnames using reverse DNS.
- Multi-threaded scanning for faster results.
- Outputs results in a tabular format.

---

## Installation

1. Clone the repository or download the `network_scanner.py` file.
2. Install required dependencies:

   ```bash
   pip install scapy
