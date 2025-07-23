#!/usr/bin/env python3
"""
Network Topology Visualizer using NetworkX and Matplotlib
Advanced: Device types, labels, gateway highlight, multiple exports, statistics/report
"""

import os
from datetime import datetime
from typing import List, Dict, Any, Optional

try:
    import networkx as nx
    import matplotlib.pyplot as plt
    import matplotlib.patches as patches
    from matplotlib.patches import FancyBboxPatch
except ImportError:
    print("Required packages not installed. Install with: pip install networkx matplotlib")
    exit(1)

class TopologyVisualizer:
    """Network topology visualization class with advanced features"""

    def __init__(self):
        self.graph = None
        self.figure_size = (12, 8)
        self.node_colors = {
            'gateway': '#D7263D',     # Red for gateway/router
            'local': '#1B9AAA',       # Teal for local machine
            'device': '#4472CA',      # Blue for other devices
            'vm': '#F29E4C',          # Orange for VMs
            'unknown': '#7C7C7C'      # Grey for unknown devices
        }
        self.output_dir = 'output'
        os.makedirs(self.output_dir, exist_ok=True)

    def create_graph_from_scan_data(self, scan_data: List[Dict[str, Any]]) -> nx.Graph:
        G = nx.Graph()
        gateway_ip = self.detect_gateway(scan_data)
        G.add_node(gateway_ip, node_type='gateway', ip=gateway_ip, mac='Gateway', label=f'Gateway\n{gateway_ip}')
        local_ips = self.detect_local_ips()
        for device in scan_data:
            ip = device['ip']
            mac = device['mac']
            vendor = device.get('vendor', 'Unknown')
            node_type = self.classify_device(ip, mac, vendor, gateway_ip, local_ips)
            label = f"{ip}\n{vendor}\n{mac[:8]}...".strip()
            G.add_node(ip, ip=ip, mac=mac, vendor=vendor, node_type=node_type, label=label)
            G.add_edge(gateway_ip, ip)
        return G

    def detect_gateway(self, scan_data):
        # Look for .1 in IP range or use first IP as fallback
        if scan_data:
            first = scan_data[0]['ip']
            base = '.'.join(first.split('.')[:3])
            candidate = f"{base}.1"
            all_ips = [d['ip'] for d in scan_data]
            return candidate if candidate in all_ips else all_ips[0]
        return "192.168.1.1"

    def detect_local_ips(self):
        import socket
        local_ips = []
        try:
            hostname = socket.gethostname()
            local_ips.append(socket.gethostbyname(hostname))
        except Exception:
            pass
        return local_ips

    def classify_device(self, ip, mac, vendor, gateway_ip, local_ips):
        if ip == gateway_ip:
            return 'gateway'
        if ip in local_ips:
            return 'local'
        vm_keywords = ['vmware', 'virtualbox', 'hyper-v']
        if any(vm_kw in vendor.lower() for vm_kw in vm_keywords):
            return 'vm'
        known_vendors = ['apple', 'samsung', 'google', 'intel', 'hp', 'dell']
        if any(v in vendor.lower() for v in known_vendors):
            return 'device'
        return 'unknown'

    def setup_plot_style(self, theme='default'):
        if theme != 'default':
            plt.style.use(theme)
        plt.rcParams['figure.facecolor'] = 'white'
        plt.rcParams['axes.facecolor'] = 'white'
        plt.rcParams['font.size'] = 10
        plt.rcParams['axes.grid'] = True
        plt.rcParams['grid.alpha'] = 0.2

    def calculate_node_positions(self, G):
        gateway = [n for n, d in G.nodes(data=True) if d.get('node_type') == 'gateway']
        pos = {}
        if gateway and len(G) > 1:
            center = gateway[0]
            pos[center] = (0, 0)
            nodes = [n for n in G.nodes if n != center]
            import math
            r = 2
            for i, node in enumerate(nodes):
                theta = 2 * math.pi * i / len(nodes)
                pos[node] = (r * math.cos(theta), r * math.sin(theta))
        else:
            pos = nx.spring_layout(G, seed=42, k=0.5)
        return pos

    def draw_network_topology(self, G, output_filename, layout='circle', export_svg=False, export_pdf=False, theme='default'):
        self.setup_plot_style(theme)
        fig, ax = plt.subplots(1, 1, figsize=self.figure_size)
        pos = self.calculate_node_positions(G)
        node_colors = [self.node_colors.get(G.nodes[n].get('node_type', 'unknown'), '#888') for n in G.nodes()]
        node_sizes = [2600 if G.nodes[n].get('node_type') == 'gateway' else 1500 for n in G.nodes()]
        nx.draw_networkx_edges(G, pos, edge_color='#999', width=1.6, alpha=0.6, ax=ax)
        nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes, alpha=0.8, ax=ax)
        labels = {n: G.nodes[n].get('label', n) for n in G.nodes}
        nx.draw_networkx_labels(G, pos, labels=labels, font_size=8, font_weight='bold', ax=ax)
        ax.set_title('Network Topology Map', fontsize=16, fontweight='bold', pad=20)
        ax.set_xlabel(f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', fontsize=9)
        self.add_legend(ax)
        ax.set_xticks([])
        ax.set_yticks([])
        ax.axis('off')
        plt.tight_layout()
        base, ext = os.path.splitext(output_filename)
        png_path = os.path.join(self.output_dir, output_filename)
        plt.savefig(png_path, dpi=220, bbox_inches='tight')
        if export_svg:
            plt.savefig(os.path.join(self.output_dir, f"{base}.svg"), bbox_inches='tight')
        if export_pdf:
            plt.savefig(os.path.join(self.output_dir, f"{base}.pdf"), bbox_inches='tight')
        plt.close()
        return png_path

    def add_legend(self, ax):
        import matplotlib.patches as mpatches
        legend_elements = []
        for key, color in self.node_colors.items():
            if key != 'unknown':
                name = key.replace('vm', 'Virtual Machine').capitalize()
                legend_elements.append(mpatches.Patch(color=color, label=name))
        ax.legend(handles=legend_elements, loc='upper left', bbox_to_anchor=(0.01, 0.99))

    def create_topology(self, scan_data: List[Dict[str, Any]], output_filename: Optional[str] = None,
                        export_svg=False, export_pdf=False, theme='default') -> str:
        if not scan_data:
            raise ValueError("No scan data provided!")
        if not output_filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"network_topology_{timestamp}.png"
        print(f"Creating network topology for {len(scan_data)} devices...")
        self.graph = self.create_graph_from_scan_data(scan_data)
        output_path = self.draw_network_topology(self.graph, output_filename, export_svg=export_svg, export_pdf=export_pdf, theme=theme)
        print(f"Network topology saved as: {output_path}")
        return output_path

    def generate_network_stats(self, scan_data):
        if not scan_data:
            return {}
        vendor_count = {}
        for device in scan_data:
            vendor = device.get('vendor', 'Unknown')
            vendor_count[vendor] = vendor_count.get(vendor, 0) + 1
        ips = sorted([d['ip'] for d in scan_data])
        return {
            'total_devices': len(scan_data),
            'vendor_distribution': vendor_count,
            'ip_range': {'first': ips[0], 'last': ips[-1]} if ips else {}
        }

    def create_detailed_report(self, scan_data, extra_stats: Optional[dict]=None):
        stats = self.generate_network_stats(scan_data)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(self.output_dir, f"network_report_{timestamp}.txt")
        with open(report_file, 'w') as f:
            f.write("NETWORK TOPOLOGY REPORT\n" + "="*27 + "\n")
            f.write(f"Generated: {datetime.now()}\n")
            f.write(f"Total Devices: {stats['total_devices']}\n")
            if 'ip_range' in stats:
                f.write(f"IP Range: {stats['ip_range'].get('first','')} - {stats['ip_range'].get('last','')}\n")
            f.write("\nDEVICE DETAILS:\n" + "-"*17 + "\n")
            for d in scan_data:
                f.write(f"IP: {d['ip']} | MAC: {d['mac']} | Vendor: {d.get('vendor','Unknown')}\n")
            f.write("\nVENDOR DISTRIBUTION:\n" + "-"*22 + "\n")
            for v, c in stats['vendor_distribution'].items():
                f.write(f"{v}: {c} device(s)\n")
            if extra_stats:
                f.write("\nEXTRA STATS:\n" + "-"*15 + "\n")
                for k, val in extra_stats.items():
                    f.write(f"{k}: {val}\n")
        print(f"Detailed report saved as: {report_file}")
        return report_file

# Basic test run
if __name__ == "__main__":
    sample_data = [
        {'ip': '192.168.1.100', 'mac': '00:11:22:33:44:55', 'vendor': 'Apple'},
        {'ip': '192.168.1.1', 'mac': '11:22:33:44:55:66', 'vendor': 'Cisco'},
        {'ip': '192.168.1.110', 'mac': '00:AA:BB:CC:DD:EE', 'vendor': 'VMware'},
        {'ip': '192.168.1.105', 'mac': '00:FF:EE:DD:CC:BB', 'vendor': 'Dell'},
    ]
    visualizer = TopologyVisualizer()
    file = visualizer.create_topology(sample_data, export_svg=True, export_pdf=True)
    report = visualizer.create_detailed_report(sample_data)
    print(f"Visualization image: {file}\nReport file: {report}")

