# Network Scanner

A multithreaded Python-based network scanning tool designed for network administrators, cybersecurity students, and security professionals. The scanner identifies active hosts, detects open TCP ports, performs basic service enumeration, and attempts banner grabbing for discovered services.

## Features

* Network and host scanning using CIDR notation
* Multi-threaded port scanning for faster results
* Open TCP port detection
* Service identification for common ports
* Basic banner grabbing
* Reverse DNS hostname lookup
* Configurable timeout and thread count
* Detailed scan summary and reporting

## Requirements

* Python 3.7+
* Standard Python libraries only (no external dependencies)

## Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/network-scanner.git
cd network-scanner
```

## Usage

### Scan a Network

```bash
python network_scanner.py 192.168.1.0/24
```

### Scan Specific Ports

```bash
python network_scanner.py 192.168.1.1 -p 1-1000
```

### Scan Multiple Ports

```bash
python network_scanner.py 10.0.0.1 -p 80,443,8080
```

### Adjust Thread Count

```bash
python network_scanner.py 192.168.1.0/24 -t 200
```

### Set Custom Timeout

```bash
python network_scanner.py 192.168.1.1 --timeout 2
```

## Command-Line Arguments

| Argument      | Description                         |
| ------------- | ----------------------------------- |
| target        | Target IP address or CIDR range     |
| -p, --ports   | Port range or comma-separated ports |
| -t, --threads | Number of scanning threads          |
| --timeout     | Socket timeout in seconds           |

## Example Output

```text
[+] Host: 192.168.1.10
    Hostname: server.local

    Open Ports:
       22/tcp   SSH            OpenSSH Server
       80/tcp   HTTP           Apache Web Server
      443/tcp   HTTPS          No banner
```

## Project Structure

```text
network_scanner.py
README.md
```

## Disclaimer

This tool is intended for educational purposes and authorized security assessments only. Always obtain explicit permission before scanning any network or system. Unauthorized network scanning may violate local laws, organizational policies, or terms of service.

## Future Improvements

* UDP scanning support
* OS fingerprinting
* Service version detection
* Export results to JSON/CSV
* ICMP ping sweep
* Web-based dashboard
* Vulnerability integration

## License

This project is released under the MIT License.
