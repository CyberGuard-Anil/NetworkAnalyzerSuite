#!/usr/bin/env python3
"""
NetworkAnalyzerSuite Setup Script
Guides users through environment and dependency setup for the suite
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

class NetworkAnalyzerSetup:
    """Setup assistant for NetworkAnalyzerSuite"""

    def __init__(self):
        self.project_root = Path(__file__).parent
        self.python_version = f"{sys.version_info.major}.{sys.version_info.minor}"
        self.system = platform.system()
        self.errors = []

    def print_header(self):
        print("="*65)
        print("       NETWORK ANALYZER SUITE – SETUP ASSISTANT")
        print("="*65)
        print(f" Python Version : {self.python_version}")
        print(f" System         : {self.system}")
        print(f" Project Path   : {self.project_root}")
        print("="*65)

    def check_python_version(self):
        print("\n[1] Python Version Check")
        if sys.version_info >= (3, 8):
            print(f"   ✔ Python {self.python_version} is compatible")
            return True
        else:
            print(f"   ✖ Python {self.python_version} is too old (requires 3.8+)")
            self.errors.append("Python version too old")
            return False

    def check_privileges(self):
        print("\n[2] Privilege Check")
        if self.system == 'Windows':
            try:
                import ctypes
                if ctypes.windll.shell32.IsUserAnAdmin():
                    print("   ✔ Running with administrator privileges")
                else:
                    print("   ! Not running as administrator (needed for packet sniffing)")
            except:
                print("   ! Could not check administrator status")
        else:
            if hasattr(os, 'geteuid') and os.geteuid() == 0:
                print("   ✔ Running as root")
            else:
                print("   ! Not running as root (needed for packet sniffing)")
                print("   Tip: Run with: sudo python3 setup.py")

    def create_directories(self):
        print("\n[3] Creating Essential Directories")
        directories = ['output', 'demo', 'logs']
        for directory in directories:
            dir_path = self.project_root / directory
            try:
                dir_path.mkdir(exist_ok=True)
                print(f"   ✔ {directory} directory ready")
            except Exception as e:
                print(f"   ✖ Error creating {directory}: {e}")
                self.errors.append(f"Directory creation failed: {directory}")

    def install_dependencies(self):
        print("\n[4] Python Dependencies")
        requirements_file = self.project_root / 'requirements.txt'
        if not requirements_file.exists():
            print("   ✖ requirements.txt not found")
            self.errors.append("requirements.txt missing")
            return
        try:
            print("   Installing from requirements.txt...")
            subprocess.check_call([
                sys.executable, '-m', 'pip', 'install', '-r', str(requirements_file)
            ])
            print("   ✔ Dependencies installed")
        except subprocess.CalledProcessError as e:
            print(f"   ✖ Failed to install dependencies: {e}")
            self.errors.append("Dependency installation failed")

    def install_system_dependencies(self):
        print("\n[5] System-Level Dependencies")
        if self.system == 'Linux':
            print("   Linux detected. Checking for required development packages...")
            commands_to_try = [
                ['dpkg', '-l', 'python3-dev'],      # Debian/Ubuntu
                ['rpm', '-qa', 'python3-devel'],    # RedHat/CentOS
            ]
            found = False
            for cmd in commands_to_try:
                try:
                    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    found = True
                    break
                except:
                    continue
            if found:
                print("   ✔ Development packages detected")
            else:
                print("   ! Development packages not found")
                print("   How to install:")
                print("     Ubuntu/Debian: sudo apt-get install python3-dev libpcap-dev")
                print("     CentOS/RHEL : sudo yum install python3-devel libpcap-devel")
        elif self.system == 'Windows':
            print("   Windows detected. Python dependencies should auto-install.")
            print("   If problems occur, try WSL or install WinPcap/Npcap.")
        elif self.system == 'Darwin':
            print("   macOS detected. Checking for Xcode tools...")
            try:
                subprocess.run(['xcode-select', '--version'], check=True, stdout=subprocess.DEVNULL)
                print("   ✔ Xcode command line tools installed")
            except:
                print("   ! Xcode command line tools not found.")
                print("   Install with: xcode-select --install")

    def test_imports(self):
        print("\n[6] Required Python Modules")
        modules = [
            ('scapy', 'scapy.all'),
            ('networkx', 'networkx'),
            ('matplotlib', 'matplotlib.pyplot'),
        ]
        for module_name, import_name in modules:
            try:
                __import__(import_name)
                print(f"   ✔ {module_name} import successful")
            except ImportError as e:
                print(f"   ✖ {module_name} import failed - {e}")
                self.errors.append(f"Module import failed: {module_name}")

    def test_basic_functionality(self):
        print("\n[7] Main Module Check")
        sys.path.insert(0, str(self.project_root))
        # Test network scanner functionality
        try:
            from scanner.network_scanner import scan_network_menu
            print("   ✔ Network Scanner import OK")
        except Exception as e:
            print(f"   ✖ Network Scanner: {e}")
            self.errors.append("Network Scanner test failed")
        # Test visualizer
        try:
            from visualizer.topology_visualizer import TopologyVisualizer
            _ = TopologyVisualizer()
            print("   ✔ Topology Visualizer import OK")
        except Exception as e:
            print(f"   ✖ Topology Visualizer: {e}")
            self.errors.append("Topology Visualizer test failed")
        # Test sniffer
        try:
            from sniffer.packet_sniffer import PacketSniffer
            _ = PacketSniffer()
            print("   ✔ Packet Sniffer import OK")
        except Exception as e:
            print(f"   ✖ Packet Sniffer: {e}")
            self.errors.append("Packet Sniffer test failed")

    def create_demo_files(self):
        print("\n[8] Creating Demo Files")
        sample_data = {
            "scan_info": {
                "timestamp": "2024-01-15T10:30:45",
                "target_network": "192.168.1.0/24",
                "total_devices": 3
            },
            "devices": [
                {
                    "ip": "192.168.1.100",
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "vendor": "Apple",
                    "timestamp": "2024-01-15T10:30:45"
                },
                {
                    "ip": "192.168.1.101",
                    "mac": "11:22:33:44:55:66",
                    "vendor": "Samsung",
                    "timestamp": "2024-01-15T10:30:46"
                },
                {
                    "ip": "192.168.1.102",
                    "mac": "aa:bb:cc:11:22:33",
                    "vendor": "Unknown",
                    "timestamp": "2024-01-15T10:30:47"
                }
            ]
        }
        try:
            import json
            demo_file = self.project_root / 'demo' / 'sample_scan_results.json'
            with open(demo_file, 'w') as f:
                json.dump(sample_data, f, indent=2)
            print("   ✔ Sample scan results created in demo/")
        except Exception as e:
            print(f"   ✖ Could not create sample: {e}")

    def print_summary(self):
        print("\n" + "="*65)
        print(" SETUP SUMMARY")
        print("="*65)
        if not self.errors:
            print(" Setup completed successfully!\n")
            print(" Run the suite with:")
            print("   sudo python3 main.py")
            print("\n Documentation:")
            print("   cat README.md\n")
        else:
            print(" Setup completed with issues:")
            for error in self.errors:
                print(f"   ✖ {error}")
            print("\n Please solve these issues before using the app.")
        print(" Useful Commands:")
        print("   pip install -r requirements.txt")
        print("   python3 main.py")
        print("   sudo python3 main.py")
        print("="*65)

    def run_setup(self):
        self.print_header()
        self.check_python_version()
        self.check_privileges()
        self.create_directories()
        self.install_dependencies()
        self.install_system_dependencies()
        self.test_imports()
        self.test_basic_functionality()
        self.create_demo_files()
        self.print_summary()

if __name__ == "__main__":
    setup = NetworkAnalyzerSetup()
    setup.run_setup()

