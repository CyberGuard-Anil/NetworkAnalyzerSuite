# 📊 NetworkAnalyzerSuite

**A comprehensive network analysis tool built with Python that combines network scanning, topology visualization, and packet sniffing capabilities into a single, user-friendly application.**

![Python](https://img.shields.io/badge/python-v3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey.svg)

## 🚀 Features

- **🔍 Network Scanner**: ARP-based host discovery to find all active devices on your network
- **🖼️ Topology Visualizer**: Generate beautiful network topology diagrams using NetworkX and matplotlib
- **📡 Packet Sniffer**: Live network traffic analysis with protocol identification and logging
- **📊 Interactive Menu**: User-friendly command-line interface with numbered options
- **💾 Data Export**: Save results in JSON format and generate detailed reports
- **🛡️ Security Focused**: Proper privilege handling and ethical usage guidelines

## 📦 Project Structure

```
NetworkAnalyzerSuite/
│
├── README.md                       # This file - project documentation
├── requirements.txt                # Python package dependencies
├── main.py                         # Main controller script with menu interface
│
├── scanner/
│   ├── __init__.py
│   └── network_scanner.py          # ARP-based network scanner implementation
│
├── visualizer/
│   ├── __init__.py
│   └── topology_visualizer.py     # NetworkX topology visualization
│
├── sniffer/
│   ├── __init__.py
│   └── packet_sniffer.py          # Live packet sniffer with protocol analysis
│
├── utils/
│   ├── __init__.py
│   └── helpers.py                 # Utility functions and system helpers
│
├── output/
│   ├── scan_results_*.json        # Network scan results (auto-generated)
│   ├── network_topology_*.png     # Topology visualizations (auto-generated)
│   └── sniff_logs_*.txt           # Packet sniffing logs (auto-generated)
│
└── demo/
    └── sample_topology.png        # Example network topology diagram
```

## 🛠️ Installation

### Prerequisites

- **Python 3.8+** (tested with Python 3.8, 3.9, 3.10, 3.11)
- **Ubuntu/Linux** (primary support), Windows and macOS (limited support)
- **Root/Administrator privileges** (required for packet sniffing)

### Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/NetworkAnalyzerSuite.git
cd NetworkAnalyzerSuite
```

### Step 2: Create Virtual Environment (Recommended)

```bash
# Create virtual environment
python3 -m venv network_analyzer_env

# Activate virtual environment
# On Linux/macOS:
source network_analyzer_env/bin/activate

# On Windows:
network_analyzer_env\Scripts\activate
```

### Step 3: Install Dependencies

```bash
# Install required packages
pip install -r requirements.txt

# Verify installation
python -c "import scapy, networkx, matplotlib; print('✅ All dependencies installed successfully!')"
```

### Step 4: Install System Dependencies (Linux)

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3-dev libpcap-dev

# CentOS/RHEL/Fedora
sudo yum install python3-devel libpcap-devel
# or for newer versions:
sudo dnf install python3-devel libpcap-devel
```

## 🚀 Usage

### Quick Start

```bash
# Run the main application (requires root for packet sniffing)
sudo python3 main.py
```

### Menu Interface

When you run the application, you'll see an interactive menu:

```
══════════════════════════════════════════════════════════════════════
                      🦈  NetworkAnalyzerSuite  👁️
               Hack the network. Visualize the unknown.

               🔍 Scan   |   🌐 Topology   |   🤖 Sniffer

          Developed with ❤️  by Anil Yadav (Ethical Hacker)
══════════════════════════════════════════════════════════════════════

══════════════════════════════════════════════════════════════════════
                         🔧 MAIN MENU 🔧
══════════════════════════════════════════════════════════════════════
   1. Scan Network & Save Results
   2. Visualize Network Topology
   3. Start Packet Sniffer (Live Logs)
   4. Exit
══════════════════════════════════════════════════════════════════════

Select an option [1-4]: _

```

### Individual Module Usage

#### Network Scanner
```python
from scanner.network_scanner import NetworkScanner

# Create scanner instance
scanner = NetworkScanner()

# Scan local network
devices = scanner.scan_network()

# Display results
scanner.display_results(devices)
```

#### Topology Visualizer
```python
from visualizer.topology_visualizer import TopologyVisualizer

# Create visualizer
visualizer = TopologyVisualizer()

# Load scan data and create topology
scan_data = [...] # From network scanner
output_file = visualizer.create_topology(scan_data)
```

#### Packet Sniffer
```python
from sniffer.packet_sniffer import PacketSniffer

# Create sniffer (requires root)
sniffer = PacketSniffer()

# Start sniffing (Ctrl+C to stop)
sniffer.start_sniffing(count=100)
```

## 📊 Output Examples

### Network Scan Results
```json
{
  "scan_info": {
    "timestamp": "2024-01-15T10:30:45",
    "target_network": "192.168.1.0/24",
    "total_devices": 5
  },
  "devices": [
    {
      "ip": "192.168.1.100",
      "mac": "aa:bb:cc:dd:ee:ff",
      "vendor": "Apple",
      "timestamp": "2024-01-15T10:30:45"
    }
  ]
}
```

### Packet Sniffing Logs
```
2024-01-15 10:35:20 - INFO - Packet #1: TCP 192.168.1.100 -> 8.8.8.8 (66 bytes) Port: 54321 -> 443 Service: HTTPS
2024-01-15 10:35:21 - INFO - Packet #2: UDP 192.168.1.1 -> 192.168.1.255 (342 bytes) Port: 67 -> 68 Service: DHCP
```

## 🔧 Configuration

### Customizing Network Range
```python
# In scanner/network_scanner.py
scanner = NetworkScanner()
devices = scanner.scan_network("10.0.0.0/24")  # Custom network range
```

### Visualization Settings
```python
# In visualizer/topology_visualizer.py
visualizer = TopologyVisualizer()
visualizer.figure_size = (16, 12)  # Larger figure
visualizer.node_colors['device'] = '#FF5733'  # Custom colors
```

### Packet Filtering
```python
# In sniffer/packet_sniffer.py
sniffer = PacketSniffer()
sniffer.sniff_with_filter("tcp port 80", count=50)  # HTTP traffic only
```

## 🛡️ Security & Ethics

### ⚠️ Important Security Notice

This tool is designed for **educational purposes** and **authorized network analysis only**. Users are responsible for:

- **Obtaining proper authorization** before scanning networks they don't own
- **Complying with local laws** and regulations regarding network analysis
- **Using root privileges responsibly** and only when necessary
- **Respecting privacy** and confidentiality of network data

### Root Privileges

Some features require root/administrator privileges:
- **Packet sniffing**: Requires raw socket access
- **ARP scanning**: May require elevated privileges on some systems

```bash
# Check if running with appropriate privileges
sudo python3 -c "
import os
print('Running as root:', os.geteuid() == 0)
"
```

## 🐛 Troubleshooting

### Common Issues

#### 1. "Permission denied" errors
```bash
# Solution: Run with sudo
sudo python3 main.py
```

#### 2. "Module 'scapy' not found"
```bash
# Solution: Install in the same environment
pip install scapy
# or
pip install -r requirements.txt
```

#### 3. "No module named 'tkinter'" (for matplotlib)
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# CentOS/RHEL
sudo yum install tkinter
# or
sudo dnf install python3-tkinter
```

#### 4. Empty scan results
- Check network connectivity
- Verify correct network range
- Ensure firewall isn't blocking ARP requests
- Try running with sudo

### Debug Mode

Enable verbose output for troubleshooting:
```python
# In network_scanner.py
scanner = NetworkScanner()
scanner.verbose = True
```

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature-name`
3. **Make your changes** and add tests
4. **Follow PEP 8** style guidelines
5. **Commit your changes**: `git commit -m "Add feature description"`
6. **Push to the branch**: `git push origin feature-name`
7. **Open a Pull Request**

### Development Setup

```bash
# Install development dependencies
pip install pytest black flake8

# Run tests
python -m pytest

# Format code
black .

# Check code style
flake8 .
```

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Your Name**
- GitHub: [@CyberGuard-Anil](https://github.com/CyberGuard-Anil)
- Email: neatrootshack@gmail.com

## 🙏 Acknowledgments

- **[Scapy](https://scapy.net/)** - The Python packet manipulation library
- **[NetworkX](https://networkx.org/)** - Network analysis and graph generation
- **[Matplotlib](https://matplotlib.org/)** - Data visualization and plotting
- **Community contributors** and testers

## 📚 Additional Resources

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [NetworkX Tutorial](https://networkx.org/documentation/stable/tutorial.html)
- [Ethical Hacking Guidelines](https://www.eccouncil.org/ethical-hacking/)
- [Python Network Programming](https://realpython.com/python-sockets/)

## 🔄 Version History

- **v1.0.0** (2024-01-15)
  - Initial release
  - ARP-based network scanning
  - Network topology visualization
  - Live packet sniffing
  - Interactive menu interface

---

⭐ **If you find this project helpful, please consider giving it a star!** ⭐

**Happy Network Analysis!** 🚀

