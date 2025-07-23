#!/usr/bin/env python3
"""
NetworkAnalyzerSuite - Main Controller Script
Author: Anil Yadav
Modern hacker-style CLI with colorful themed output and emojis.
"""

import os
import sys
import json
from datetime import datetime
from colorama import Fore, Style, init

# Enable ANSI colors on Windows
init(autoreset=True)

try:
    from scanner.network_scanner import scan_network_menu
    from visualizer.topology_visualizer import TopologyVisualizer
    from sniffer.packet_sniffer import PacketSniffer
    from utils.helpers import create_directories, validate_root_access, print_banner
except ImportError as e:
    print(Fore.RED + Style.BRIGHT + f"Error importing modules: {e}")
    print(Fore.RED + "Please ensure all required modules are in the correct directories")
    sys.exit(1)

class NetworkAnalyzerSuite:
    def __init__(self):
        self.topology_visualizer = TopologyVisualizer()
        self.sniffer = PacketSniffer()
        self.create_output_directories()

    def create_output_directories(self):
        directories = ['output', 'demo']
        create_directories(directories)

    def print_header(self):
        print(Fore.LIGHTGREEN_EX + Style.BRIGHT + "\n" + "═"*70)
        print(Fore.CYAN + Style.BRIGHT + "{:^70}".format("🦈  NetworkAnalyzerSuite  👁️"))
        print(Fore.LIGHTYELLOW_EX + Style.NORMAL + "{:^70}".format("Hack the network. Visualize the unknown."))
        print("{:^70}".format(""))
        print(Fore.LIGHTCYAN_EX + Style.BRIGHT + "{:^70}".format("🔍 Scan   |   🌐 Topology   |   🤖 Sniffer"))
        print("{:^70}".format(""))
        print(Fore.MAGENTA + Style.BRIGHT + "{:^70}".format("Developed with ❤️  by Anil Yadav (Ethical Hacker)"))
        print(Fore.LIGHTGREEN_EX + Style.BRIGHT + "═"*70 + "\n")

    def print_main_menu(self, last_action=None):
        print(Fore.LIGHTBLUE_EX + Style.BRIGHT + "\n" + "═"*50)
        print(Fore.LIGHTWHITE_EX + Style.BRIGHT + "{:^50}".format("🔧 MAIN MENU 🔧"))
        print(Fore.LIGHTBLUE_EX + Style.BRIGHT + "═"*50)
        options = [
            "1. Scan Network & Save Results",
            "2. Visualize Network Topology",
            "3. Start Packet Sniffer (Live Logs)",
            "4. Exit"
        ]
        for opt in options:
            print(Fore.LIGHTCYAN_EX + f"   {opt}")
        print(Fore.LIGHTBLUE_EX + Style.BRIGHT + "═"*50)
        if last_action:
            print(Fore.YELLOW + Style.BRIGHT + f"Last: {last_action}\n")

    def scan_network(self):
        print(Fore.CYAN + Style.BRIGHT + "\n[SCANNER] Network scanning started...")
        try:
            results = scan_network_menu()
            if not results:
                print(Fore.LIGHTRED_EX + Style.BRIGHT + "❌ No devices discovered or scan aborted.\n")
                return "Scan aborted"
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"output/scan_results_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            print(Fore.LIGHTGREEN_EX + Style.BRIGHT + f"✅ Scan completed! {len(results)} device(s) saved to {filename}")
            for device in results:
                print(Fore.LIGHTWHITE_EX + f"  {device['ip']} - {device['mac']}")
            return f"Network scan ({len(results)} found)"
        except Exception as e:
            print(Fore.RED + Style.BRIGHT + f"Error during scanning: {e}\n")
            return "Scan error"

    def visualize_topology(self):
        print(Fore.CYAN + Style.BRIGHT + "\n[VISUALIZER] Creating network topology...")
        try:
            scan_files = [f for f in os.listdir('output') if f.startswith('scan_results_') and f.endswith('.json')]
            if not scan_files:
                print(Fore.RED + Style.BRIGHT + "❌ No scan results found. Please run a network scan first.\n")
                return "No scan data"
            latest_scan = sorted(scan_files)[-1]
            filepath = f"output/{latest_scan}"
            with open(filepath, 'r') as f:
                scan_data = json.load(f)
            export_svg = input("Export SVG as well? (y/n): ").strip().lower() == 'y'
            export_pdf = input("Export PDF as well? (y/n): ").strip().lower() == 'y'
            theme = input("Theme (default/ggplot/fivethirtyeight): ").strip().lower() or 'default'
            output_file = self.topology_visualizer.create_topology(
                scan_data,
                export_svg=export_svg,
                export_pdf=export_pdf,
                theme=theme
            )
            print(Fore.LIGHTGREEN_EX + Style.BRIGHT + f"✅ Network diagram saved as: {output_file}")
            want_report = input("Generate detailed report? (y/n): ").strip().lower() == 'y'
            if want_report:
                self.topology_visualizer.create_detailed_report(scan_data)
            return "Topology visualized"
        except Exception as e:
            print(Fore.RED + Style.BRIGHT + f"Error during visualization: {e}\n")
            return "Visualization error"

    def start_packet_sniffer(self):
        print(Fore.CYAN + Style.BRIGHT + "\n[SNIFFER] Starting packet capture...")
        if not validate_root_access():
            print(Fore.RED + Style.BRIGHT + "❌ Root access required for packet sniffing!")
            return "Sniffer failed"
        try:
            self.sniffer.sniff_with_menu()
            want_summary = input("Export session summary? (y/n): ").strip().lower() == 'y'
            if want_summary:
                self.sniffer.save_session_summary()
            return "Packet sniffed"
        except KeyboardInterrupt:
            print(Fore.YELLOW + Style.BRIGHT + "\nPacket sniffer stopped by user")
            return "Sniffer interrupted"
        except Exception as e:
            print(Fore.RED + Style.BRIGHT + f"Error during packet sniffing: {e}\n")
            return "Sniffer error"

    def run(self):
        self.print_header()
        last_action = None
        while True:
            try:
                self.print_main_menu(last_action)
                choice = input(Fore.LIGHTCYAN_EX + Style.BRIGHT + "Select an option [1-4]: ").strip()
                if choice == '1':
                    last_action = self.scan_network()
                elif choice == '2':
                    last_action = self.visualize_topology()
                elif choice == '3':
                    last_action = self.start_packet_sniffer()
                elif choice == '4':
                    print(Fore.LIGHTGREEN_EX + Style.BRIGHT + "\nThank you for using NetworkAnalyzerSuite!\n")
                    break
                else:
                    print(Fore.RED + Style.BRIGHT + "Invalid choice. Please select 1-4.\n")
                input(Fore.MAGENTA + Style.BRIGHT + "\n(Press Enter for Menu...)")
            except KeyboardInterrupt:
                print(Fore.RED + Style.BRIGHT + "\nProgram interrupted. Goodbye.")
                break
            except Exception as e:
                print(Fore.RED + Style.BRIGHT + f"Unexpected error: {e}\n")
                last_action = "Menu error"

def main():
    try:
        app = NetworkAnalyzerSuite()
        app.run()
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

