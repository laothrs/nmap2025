# nmap2025

**nmap2025** is a modern, asynchronous network scanning tool written in Python. It is designed to provide fast and detailed port scanning capabilities using low-level TCP/IP techniques. The project is intended for cybersecurity professionals, penetration testers, and network administrators who need deep insights into live hosts and open services.

## Features

- Asynchronous scanning for high performance
- Custom TCP SYN scanning using `scapy`
- Optional banner grabbing for open ports
- TCP timestamp and IP ID collection
- Language support (currently English and Turkish)
- Command-line interface with flexible argument parsing
- Clean JSON output for automation pipelines

## Installation

> Requires Python 3.8 or later.

1. Clone the repository:
   ```bash
   git clone https://github.com/laothrs/nmap2025.git
   cd nmap2025
Install dependencies:

bash
Copy
Edit
pip install -r requirements.txt
If not already installed, install scapy:

bash
Copy
Edit
pip install scapy
Usage
Basic scan of a single IP and port range:

bash
Copy
Edit
python laoth2025nmap.py --target 192.168.1.1 --ports 22,80,443
Scan an entire subnet with default ports:

bash
Copy
Edit
python laoth2025nmap.py --target 192.168.1.0/24
Save results to a JSON file:

bash
Copy
Edit
python laoth2025nmap.py --target 10.0.0.1 --output results.json
Language selection (English and Turkish):

bash
Copy
Edit
python laoth2025nmap.py --target 127.0.0.1 --lang tr
Command-Line Arguments
Argument	Description
--target	IP address or CIDR range
--ports	Comma-separated list of ports
--output	Save results to specified JSON file
--lang	Language: en or tr
--timeout	Timeout in seconds (default: 2)
--workers	Number of concurrent scan workers

Notes
This tool uses raw packets and may require root privileges.

It is designed for educational and authorized security testing only.

Always obtain permission before scanning networks you do not own.

License
This project is released under the MIT License. See LICENSE for more details.

Disclaimer
The author is not responsible for any misuse or illegal activity involving this tool. Use it responsibly and only on systems you are authorized to test.

yaml
Copy
Edit

---

Let me know if you'd like a `requirements.txt` or other documentation files generated.
