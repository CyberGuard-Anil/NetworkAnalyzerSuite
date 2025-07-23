import json
import socket
from scapy.all import ARP, Ether, srp, conf
import netifaces

def get_default_gateway_subnet():
    gws = netifaces.gateways()
    default_iface = gws.get('default', {}).get(netifaces.AF_INET)
    if not default_iface:
        return None
    iface_name = default_iface[1]
    ip_info = netifaces.ifaddresses(iface_name).get(netifaces.AF_INET, [{}])[0]
    ip = ip_info.get("addr")
    netmask = ip_info.get("netmask")
    if not ip or not netmask:
        return None
    # Convert netmask to CIDR
    mask = sum([bin(int(x)).count('1') for x in netmask.split('.')])
    subnet = f"{ip}/{mask}"
    base = subnet.rsplit('.', 1)[0] + ".0/" + str(mask)
    return base

def resolve_domain_to_ips(domain):
    try:
        result = socket.gethostbyname_ex(domain)
        return result[2]
    except Exception:
        return []

def perform_arp_scan(subnet):
    print(f"Scanning subnet: {subnet}")
    # Disable verbose in scapy
    conf.verb = 0
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, retry=1)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def scan_network_menu():
    print("Scan Mode:")
    print("1. Auto-detect local network")
    print("2. Enter IP range/subnet manually")
    print("3. Enter domain name to scan")
    choice = input("Choice (1-3): ").strip()
    scan_targets = []

    if choice == "1":
        subnet = get_default_gateway_subnet()
        if subnet:
            scan_targets = [subnet]
        else:
            print("Could not detect local network. Try manual input.")
            return
    elif choice == "2":
        manual = input("Enter subnet/IP range (e.g. 192.168.1.0/24): ").strip()
        scan_targets = [manual]
    elif choice == "3":
        domain = input("Enter domain name (e.g. example.com): ").strip()
        ips = resolve_domain_to_ips(domain)
        if not ips:
            print("Domain not resolved or invalid.")
            return
        print(f"Resolved IP(s): {', '.join(ips)}")
        scan_targets = ips
    else:
        print("Invalid choice.")
        return

    all_devices = []
    for target in scan_targets:
        if "/" in target:  # Subnet
            devices = perform_arp_scan(target)
        else:  # Single IP (domain resolved to IP)
            devices = perform_arp_scan(f"{target}/32")
        all_devices.extend(devices)

    ts = __import__('datetime').datetime.now().strftime("%Y%m%d_%H%M%S")
    result_file = f"output/scan_results_{ts}.json"
    with open(result_file, "w") as f:
        json.dump(all_devices, f, indent=2)
    print(f"Scan completed. {len(all_devices)} device(s) found.")
    print(f"Results saved to {result_file}")

