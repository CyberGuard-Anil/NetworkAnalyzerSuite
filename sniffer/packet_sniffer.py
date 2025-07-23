#!/usr/bin/env python3
"""
Advanced Packet Sniffer Module using Scapy
Captures and analyzes live network traffic with advanced features
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional

try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether
    from scapy.layers.dns import DNS
except ImportError:
    print("Scapy not installed. Install with: pip install scapy")
    exit(1)

class PacketSniffer:
    """Network packet sniffer class"""

    def __init__(self, interface: Optional[str] = None, log_file: str = "output/sniff_logs.txt"):
        self.interface = interface
        self.log_file = log_file
        self.packet_count = 0
        self.running = False
        self.protocol_stats = {
            'TCP': 0,
            'UDP': 0,
            'ICMP': 0,
            'Other': 0
        }
        self.captured_packets = []
        self.setup_logging()

    def setup_logging(self):
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def get_available_interfaces(self):
        try:
            return scapy.get_if_list()
        except Exception as e:
            self.logger.error(f"Error getting interfaces: {e}")
            return []

    def packet_handler(self, packet):
        self.packet_count += 1
        proto = "Other"
        summary = ""
        # IP Layer Handling
        if packet.haslayer(IP):
            ip = packet[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            if packet.haslayer(TCP):
                proto = "TCP"
                self.protocol_stats['TCP'] += 1
                tcp = packet[TCP]
                summary = f"TCP {src_ip}:{tcp.sport} -> {dst_ip}:{tcp.dport}"
                if tcp.dport == 80 or tcp.sport == 80:
                    if packet.haslayer('Raw'):
                        try:
                            data = packet['Raw'].load.decode(errors='ignore')
                            if any(method in data for method in ['GET', 'POST', 'HTTP']):
                                summary += " [HTTP] " + data.splitlines()[0]
                        except Exception:
                            pass
                if tcp.dport == 443 or tcp.sport == 443:
                    summary += " [HTTPS]"
            elif packet.haslayer(UDP):
                proto = "UDP"
                self.protocol_stats['UDP'] += 1
                udp = packet[UDP]
                summary = f"UDP {src_ip}:{udp.sport} -> {dst_ip}:{udp.dport}"
                if packet.haslayer(DNS):
                    summary += " [DNS Query]"
            elif packet.haslayer(ICMP):
                proto = "ICMP"
                self.protocol_stats['ICMP'] += 1
                icmp = packet[ICMP]
                icmp_types = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request", 11: "Time Exceeded"}
                summary = f"ICMP {src_ip} -> {dst_ip} Type: {icmp.type} ({icmp_types.get(icmp.type, '')})"
            else:
                self.protocol_stats['Other'] += 1
                summary = f"{src_ip} -> {dst_ip} (Other Protocol)"
        else:
            self.protocol_stats['Other'] += 1
            summary = f"Unknown Packet ({len(packet)} bytes)"

        self.logger.info(f"Packet #{self.packet_count}: {summary}")
        # Colorized output can be added here with ANSI codes if desired

        # Store for potential PCAP saving
        self.captured_packets.append(packet)
        if self.packet_count % 10 == 0:
            self.print_stats()

    def print_stats(self):
        print(f"\nPacket Statistics (Total: {self.packet_count})")
        print("-" * 40)
        total = self.packet_count if self.packet_count > 0 else 1
        for proto, count in self.protocol_stats.items():
            pc = (count / total) * 100
            print(f"{proto:6}: {count:4d} packets ({pc:5.1f}%)")
        print("-" * 40)

    def start_sniffing(self, count: int = 0, timeout: Optional[int] = None, filter_str: Optional[str] = None, save_pcap: bool = False):
        self.running = True
        self.packet_count = 0
        self.protocol_stats = dict(TCP=0, UDP=0, ICMP=0, Other=0)
        self.captured_packets = []

        self.logger.info("=" * 50)
        self.logger.info("PACKET SNIFFING STARTED")
        self.logger.info(f"Interface: {self.interface or 'Default'}")
        self.logger.info(f"Filter: {filter_str or 'None'}")
        self.logger.info(f"Count: {count or 'Unlimited'}")
        self.logger.info(f"Timeout: {timeout or 'None'}")
        self.logger.info("=" * 50)

        print(f"Started sniffing on interface: {self.interface or 'default'}")
        if filter_str:
            print(f"Filter: {filter_str}")
        print("Capturing packets... Press Ctrl+C to stop")

        try:
            scapy.sniff(
                iface=self.interface,
                prn=self.packet_handler,
                count=count if count > 0 else 0,
                timeout=timeout,
                filter=filter_str,
                store=False
            )
        except KeyboardInterrupt:
            print("\nSniffing stopped by user")
        except Exception as e:
            self.logger.error(f"Error during packet sniffing: {e}")
        finally:
            self.stop_sniffing(save_pcap)

    def stop_sniffing(self, save_pcap=False):
        self.running = False
        self.logger.info("=" * 50)
        self.logger.info("PACKET SNIFFING STOPPED")
        self.logger.info(f"Total packets captured: {self.packet_count}")
        for protocol, count in self.protocol_stats.items():
            pc = (count / self.packet_count) * 100 if self.packet_count else 0
            self.logger.info(f"{protocol}: {count} packets ({pc:.1f}%)")
        self.logger.info("=" * 50)
        print("\nSniffing session ended")
        self.print_stats()
        print(f"Logs saved to: {self.log_file}")

        if save_pcap and self.captured_packets:
            self.save_to_pcap()

    def save_to_pcap(self):
        from scapy.utils import wrpcap
        pcap_file = f"output/sniffed_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        try:
            wrpcap(pcap_file, self.captured_packets)
            print(f"Captured packets saved to {pcap_file}")
        except Exception as e:
            print(f"Could not save .pcap: {e}")

    def sniff_with_menu(self):
        print("Available interfaces:", ', '.join(self.get_available_interfaces()))
        iface = input("Enter interface (Leave blank for default): ").strip() or None
        filter_str = input("BPF filter (e.g. tcp, udp, icmp), blank for all: ").strip() or None
        count = input("Packets to capture (0 for unlimited): ").strip()
        timeout = input("Sniff timeout seconds (0 for unlimited): ").strip()
        save_pcap = input("Save to PCAP file? (y/n): ").lower().strip() == 'y'

        pkt_count = int(count) if count.isdigit() else 0
        pkt_timeout = int(timeout) if timeout.isdigit() and int(timeout) > 0 else None

        self.interface = iface
        self.start_sniffing(count=pkt_count, timeout=pkt_timeout, filter_str=filter_str, save_pcap=save_pcap)

    def save_session_summary(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        summary_file = f"output/sniff_summary_{timestamp}.json"
        summary = {
            'session_info': {
                'timestamp': datetime.now().isoformat(),
                'interface': self.interface or 'default',
                'total_packets': self.packet_count,
                'log_file': self.log_file
            },
            'protocol_statistics': self.protocol_stats,
        }
        try:
            with open(summary_file, 'w') as f:
                json.dump(summary, f, indent=2)
            print(f"Session summary saved to: {summary_file}")
            return summary_file
        except Exception as e:
            self.logger.error(f"Error saving session summary: {e}")
            return None

if __name__ == "__main__":
    print("Testing Packet Sniffer Module")
    sniffer = PacketSniffer()
    sniffer.sniff_with_menu()
    sniffer.save_session_summary()

