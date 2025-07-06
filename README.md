# nmap2025

nmap2025 is a modern and lightweight port scanner written in Python. It is designed to provide a fast, asynchronous, and extensible approach to network scanning. Unlike traditional scanners, nmap2025 uses low-level TCP/IP techniques via Scapy, allowing for deeper analysis and custom probing.

This tool is suitable for security researchers, penetration testers, and network administrators who require detailed insights into hosts and services.

## Features

- Asynchronous scanning for high performance
- Custom TCP SYN scans using Scapy
- Banner grabbing for open ports
- IP ID and TCP timestamp analysis
- Multi-language output (English and Turkish)
- JSON-formatted results
- Simple and flexible CLI

## Usage

```bash
python laoth2025nmap.py --target <IP or CIDR> [options]
