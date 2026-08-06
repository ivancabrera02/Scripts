# Scripts Collection

Offensive security tools and techniques for internal penetration testing

## Tools
 
### dhcp_dump.py
 
Remote MS-DHCPM enumeration tool. Extracts complete DHCP network inventory (subnets, active leases, topology) without credentials or code execution on the DHCP server.
 
**What it does:**
- Enumerate all DHCP scopes and their configuration
- List all active DHCP leases (IP, MAC, hostname)
- Discover hidden network segments (management, OT/SCADA, backup, VPN)
- Export results to CSV for further analysis
**Requirements:**
- Network access to DHCP server (TCP 445 or dynamic RPC ports)
- DHCP Users group membership or equivalent (read-only access)
- Python 3.11+ with: `pip install python-tds pycryptodome`
**Usage:**
```bash
python3 dhcp_dump.py -target 10.3.0.3 -u 'DOMAIN\user' -p 'Password' -tcp
python3 dhcp_dump.py -target 10.3.0.3 -u sa -p 'Password' -tcp -o inventory.csv
```
