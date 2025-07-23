#!/usr/bin/env python3
"""
Helper Functions for NetworkAnalyzerSuite
Utility functions for formatting, logging, and system operations
"""

import os
import sys
import pwd
import socket
import platform
import subprocess
from datetime import datetime
from typing import List, Dict, Any, Optional

def print_banner():
    """Print application banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                    NETWORK ANALYZER SUITE                    ║
    ║                                                              ║
    ║          🔍 Network Scanner  📊 Topology Visualizer         ║
    ║              📡 Packet Sniffer  🛡️  Security Tool           ║
    ║                                                              ║
    ║                    Built with Python & Scapy                ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)
    print(f"    🖥️  System: {platform.system()} {platform.release()}")
    print(f"    🐍 Python: {platform.python_version()}")
    print(f"    👤 User: {get_current_user()}")
    print(f"    📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

def get_current_user():
    """Get current username"""
    try:
        if platform.system() == 'Windows':
            import getpass
            return getpass.getuser()
        else:
            return pwd.getpwuid(os.getuid()).pw_name
    except:
        return "Unknown"

def validate_root_access():
    """Check if running with root/admin privileges"""
    try:
        if platform.system() == 'Windows':
            # Check for admin privileges on Windows
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            # Check for root on Unix-like systems
            return os.geteuid() == 0
    except:
        return False

def create_directories(directories: List[str]):
    """Create directories if they don't exist"""
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            print(f"📁 Directory created/verified: {directory}")
        except OSError as e:
            print(f"❌ Error creating directory {directory}: {e}")

def check_dependencies():
    """Check if required Python packages are installed"""
    required_packages = {
        'scapy': 'scapy',
        'networkx': 'networkx', 
        'matplotlib': 'matplotlib'
    }

    missing_packages = []

    for package_name, import_name in required_packages.items():
        try:
            __import__(import_name)
            print(f"✅ {package_name}: Installed")
        except ImportError:
            print(f"❌ {package_name}: Not installed")
            missing_packages.append(package_name)

    if missing_packages:
        print(f"\n⚠️  Missing packages: {', '.join(missing_packages)}")
        print("Install with: pip install " + " ".join(missing_packages))
        return False

    print("✅ All dependencies satisfied!")
    return True

def get_system_info():
    """Get comprehensive system information"""
    info = {
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'python_version': platform.python_version(),
        'hostname': socket.gethostname(),
        'user': get_current_user(),
        'timestamp': datetime.now().isoformat()
    }

    # Add network interface information
    try:
        info['local_ip'] = socket.gethostbyname(socket.gethostname())
    except:
        info['local_ip'] = 'Unknown'

    return info

def format_mac_address(mac: str) -> str:
    """Format MAC address with consistent formatting"""
    # Remove any existing separators and convert to uppercase
    mac_clean = mac.replace(':', '').replace('-', '').replace('.', '').upper()

    # Add colons every 2 characters
    if len(mac_clean) == 12:
        return ':'.join([mac_clean[i:i+2] for i in range(0, 12, 2)])
    else:
        return mac  # Return original if invalid format

def format_bytes(bytes_count: int) -> str:
    """Format bytes into human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.1f} PB"

def format_duration(seconds: float) -> str:
    """Format duration in seconds to human readable format"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"

def validate_ip_address(ip: str) -> bool:
    """Validate IP address format"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def validate_network_range(network: str) -> bool:
    """Validate network range in CIDR notation"""
    try:
        if '/' not in network:
            return False

        ip, prefix = network.split('/')

        # Validate IP
        if not validate_ip_address(ip):
            return False

        # Validate prefix
        prefix = int(prefix)
        if not (0 <= prefix <= 32):
            return False

        return True
    except:
        return False

def get_network_interfaces():
    """Get list of network interfaces"""
    interfaces = []

    try:
        if platform.system() == 'Windows':
            # Windows method
            import subprocess
            result = subprocess.run(['ipconfig', '/all'], 
                                  capture_output=True, text=True)
            # Parse Windows ipconfig output (simplified)
            interfaces = ['Local Area Connection', 'Wi-Fi', 'Ethernet']
        else:
            # Unix-like systems
            try:
                import netifaces
                interfaces = netifaces.interfaces()
            except ImportError:
                # Fallback method
                result = subprocess.run(['ip', 'link', 'show'], 
                                      capture_output=True, text=True)
                # Simple parsing of ip command output
                for line in result.stdout.split('\n'):
                    if ': ' in line and 'state' in line:
                        interface_name = line.split(': ')[1].split('@')[0]
                        interfaces.append(interface_name)
    except:
        interfaces = ['eth0', 'wlan0', 'lo']  # Common defaults

    return interfaces

def save_json_safely(data: Any, filename: str) -> bool:
    """Safely save data to JSON file with error handling"""
    try:
        import json

        # Create directory if it doesn't exist
        directory = os.path.dirname(filename)
        if directory:
            os.makedirs(directory, exist_ok=True)

        # Write JSON with backup
        backup_filename = f"{filename}.backup"

        with open(backup_filename, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        # If backup successful, replace original
        os.replace(backup_filename, filename)

        print(f"💾 Data saved to: {filename}")
        return True

    except Exception as e:
        print(f"❌ Error saving JSON file {filename}: {e}")
        return False

def load_json_safely(filename: str) -> Optional[Any]:
    """Safely load JSON file with error handling"""
    try:
        import json

        if not os.path.exists(filename):
            print(f"⚠️  File not found: {filename}")
            return None

        with open(filename, 'r') as f:
            data = json.load(f)

        print(f"📂 Data loaded from: {filename}")
        return data

    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON in file {filename}: {e}")
        return None
    except Exception as e:
        print(f"❌ Error loading JSON file {filename}: {e}")
        return None

def create_backup(filename: str) -> bool:
    """Create backup of existing file"""
    if not os.path.exists(filename):
        return True  # Nothing to backup

    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"{filename}.backup_{timestamp}"

        import shutil
        shutil.copy2(filename, backup_filename)

        print(f"💾 Backup created: {backup_filename}")
        return True

    except Exception as e:
        print(f"❌ Error creating backup: {e}")
        return False

def cleanup_old_files(directory: str, pattern: str, max_age_days: int = 7):
    """Clean up old files based on age"""
    try:
        import glob
        import time

        pattern_path = os.path.join(directory, pattern)
        files = glob.glob(pattern_path)

        current_time = time.time()
        max_age_seconds = max_age_days * 24 * 60 * 60

        cleaned_count = 0
        for file_path in files:
            file_age = current_time - os.path.getmtime(file_path)

            if file_age > max_age_seconds:
                os.remove(file_path)
                cleaned_count += 1
                print(f"🗑️  Removed old file: {os.path.basename(file_path)}")

        if cleaned_count > 0:
            print(f"✅ Cleaned up {cleaned_count} old files")
        else:
            print("✅ No old files to clean up")

    except Exception as e:
        print(f"❌ Error during cleanup: {e}")

def print_separator(title: str = "", char: str = "=", width: int = 60):
    """Print a formatted separator line"""
    if title:
        title_with_spaces = f" {title} "
        padding = (width - len(title_with_spaces)) // 2
        line = char * padding + title_with_spaces + char * padding
        # Ensure exact width
        if len(line) < width:
            line += char * (width - len(line))
        print(line)
    else:
        print(char * width)

def get_file_info(filename: str) -> Dict[str, Any]:
    """Get detailed file information"""
    try:
        stat_info = os.stat(filename)

        return {
            'filename': os.path.basename(filename),
            'full_path': os.path.abspath(filename),
            'size': stat_info.st_size,
            'size_formatted': format_bytes(stat_info.st_size),
            'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            'permissions': oct(stat_info.st_mode)[-3:]
        }
    except Exception as e:
        return {'error': str(e)}

def test_network_connectivity(host: str = "8.8.8.8", timeout: int = 5) -> bool:
    """Test network connectivity"""
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, 53))
        return True
    except socket.error:
        return False

def get_available_ports(start_port: int = 1024, end_port: int = 65535, 
                       host: str = 'localhost') -> List[int]:
    """Get list of available (unused) ports"""
    available_ports = []

    for port in range(start_port, min(start_port + 100, end_port)):  # Limit check
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((host, port))
                available_ports.append(port)
        except OSError:
            continue  # Port in use

        if len(available_ports) >= 10:  # Limit results
            break

    return available_ports

# Example usage and testing
if __name__ == "__main__":
    print("🧪 Testing Helper Functions")

    print_banner()

    print("\n🔍 System Information:")
    system_info = get_system_info()
    for key, value in system_info.items():
        print(f"  {key}: {value}")

    print("\n🔧 Dependencies Check:")
    check_dependencies()

    print("\n🌐 Network Connectivity:")
    connected = test_network_connectivity()
    print(f"  Internet connectivity: {'✅ OK' if connected else '❌ Failed'}")

    print("\n📁 Creating test directories:")
    create_directories(['test_output', 'test_logs'])

    print("\n✅ Helper functions test completed!")

