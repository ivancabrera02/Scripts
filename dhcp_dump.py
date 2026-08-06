#!/usr/bin/env python3
"""
dhcp_dump.py - MS-DHCPM Remote DHCP Subnet & Lease Enumeration

First offensive tool implementing remote MS-DHCPM RPC enumeration.
Previously only used by malware (NotPetya/BadRabbit) via local API.
This tool does it remotely over the wire via \\PIPE\\dhcpserver.

Requires: impacket (pip install impacket)
          Python 3.9-3.11 recommended (3.13 has compatibility issues)

Usage:
    python3 dhcp_dump.py -target 10.0.1.1 -u jsmith -p Password1 -d contoso.com
    python3 dhcp_dump.py -target 10.0.1.1 -u jsmith -H :NTHASH -d contoso.com
    python3 dhcp_dump.py -target 10.0.1.1 -u jsmith -p Password1 -d contoso.com -tcp

Minimum access: DHCP Users group membership (read-only)
"""

import sys
import struct
import socket
import argparse
from collections import defaultdict

try:
    from impacket.dcerpc.v5 import transport, epm
    from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    from impacket import uuid
except ImportError:
    print("[-] Impacket required: pip install impacket")
    print("[-] Python 3.9-3.11 recommended for compatibility")
    sys.exit(1)


# ============================================================
# MS-DHCPM Protocol Constants
# ============================================================

# dhcpsrv interface UUID
MSRPC_UUID_DHCPSRV = uuid.uuidtup_to_bin(
    ('6BFFD098-A112-3610-9833-46C3F874532D', '1.0')
)

# Opnums
OPNUM_GET_SUBNET_INFO     = 2
OPNUM_ENUM_SUBNETS        = 3
OPNUM_ENUM_SUBNET_CLIENTS = 20

# Win32 error codes
ERROR_SUCCESS   = 0
ERROR_MORE_DATA = 234
ERROR_ACCESS_DENIED = 5
ERROR_NO_MORE_ITEMS = 259


# ============================================================
# NDR Helper Parser
# ============================================================

class NDRParser:
    """
    Minimal NDR response stub parser.
    Handles DWORD, unique pointers, conformant arrays,
    and conformant varying strings (LPWSTR).
    """

    def __init__(self, data):
        if isinstance(data, bytearray):
            self.data = bytes(data)
        else:
            self.data = data
        self.offset = 0

    def read_dword(self):
        val = struct.unpack_from('<I', self.data, self.offset)[0]
        self.offset += 4
        return val

    def read_ptr(self):
        """Read unique pointer referent ID, return True if non-null."""
        return self.read_dword() != 0

    def align(self, boundary=4):
        rem = self.offset % boundary
        if rem != 0:
            self.offset += boundary - rem

    def read_ip(self):
        """Read DHCP_IP_ADDRESS (DWORD in host byte order) as string."""
        dword = self.read_dword()
        return socket.inet_ntoa(struct.pack('!I', dword))

    def read_ip_raw(self):
        """Read DHCP_IP_ADDRESS and return both string and integer."""
        dword = self.read_dword()
        return socket.inet_ntoa(struct.pack('!I', dword)), dword

    def read_cvstring(self):
        """
        Read NDR conformant varying string (LPWSTR).
        Assumes the pointer referent ID was already consumed.
        Layout: max_count(4) + offset(4) + actual_count(4) + UTF-16LE data
        """
        max_count = self.read_dword()
        _ = self.read_dword()  # offset (always 0)
        actual_count = self.read_dword()
        byte_len = actual_count * 2
        raw = self.data[self.offset:self.offset + byte_len]
        self.offset += byte_len
        self.align()
        try:
            return raw.decode('utf-16-le').rstrip('\x00')
        except UnicodeDecodeError:
            return raw.hex()

    def read_lpwstr(self):
        """Read a full LPWSTR (unique pointer + string data)."""
        if not self.read_ptr():
            return None
        return self.read_cvstring()

    def read_conformant_bytes(self, expected_len):
        """
        Read NDR conformant byte array.
        Layout: max_count(4) + data[max_count]
        """
        max_count = self.read_dword()
        raw = self.data[self.offset:self.offset + expected_len]
        self.offset += expected_len
        self.align()
        return raw

    def remaining(self):
        return len(self.data) - self.offset


# ============================================================
# NDR Request Builders
# ============================================================

def build_enum_subnets(resume_handle=0, preferred_max=65536):
    """Build R_DhcpEnumSubnets (opnum 3) request stub."""
    stub = struct.pack('<I', 0)               # ServerIpAddress = NULL
    stub += struct.pack('<I', resume_handle)   # ResumeHandle
    stub += struct.pack('<I', preferred_max)   # PreferredMaximum
    return stub


def build_get_subnet_info(subnet_ip):
    """Build R_DhcpGetSubnetInfo (opnum 2) request stub."""
    ip_int = struct.unpack('!I', socket.inet_aton(subnet_ip))[0]
    stub = struct.pack('<I', 0)        # ServerIpAddress = NULL
    stub += struct.pack('<I', ip_int)  # SubnetAddress
    return stub


def build_enum_clients(subnet_ip, resume_handle=0, preferred_max=65536):
    """Build R_DhcpEnumSubnetClients (opnum 21) request stub."""
    ip_int = struct.unpack('!I', socket.inet_aton(subnet_ip))[0]
    stub = struct.pack('<I', 0)               # ServerIpAddress = NULL
    stub += struct.pack('<I', ip_int)          # SubnetAddress
    stub += struct.pack('<I', resume_handle)   # ResumeHandle
    stub += struct.pack('<I', preferred_max)   # PreferredMaximum
    return stub


# ============================================================
# NDR Response Parsers
# ============================================================

def parse_enum_subnets_response(data):
    """
    Parse R_DhcpEnumSubnets response.

    Response layout:
      ResumeHandle:   DWORD
      EnumInfo:       unique ptr → DHCP_IP_ARRAY {
                          NumElements: DWORD,
                          Elements:    unique ptr → conformant DWORD[]
                      }
      ElementsRead:   DWORD
      ElementsTotal:  DWORD
      ReturnValue:    DWORD
    """
    p = NDRParser(data)
    resume = p.read_dword()
    subnets = []

    if p.read_ptr():  # EnumInfo
        num_elements = p.read_dword()
        if p.read_ptr():  # Elements array
            _ = p.read_dword()  # max_count (conformant)
            for _ in range(num_elements):
                subnets.append(p.read_ip())

    elements_read = p.read_dword()
    elements_total = p.read_dword()
    ret_val = p.read_dword()

    return subnets, resume, ret_val


def parse_get_subnet_info_response(data):
    """
    Parse R_DhcpGetSubnetInfo response.

    Response layout:
      SubnetInfo: unique ptr → DHCP_SUBNET_INFO {
          SubnetAddress:  DWORD
          SubnetMask:     DWORD
          SubnetName:     LPWSTR
          SubnetComment:  LPWSTR
          PrimaryHost:    DHCP_HOST_INFO {
              IpAddress:    DWORD
              NetBiosName:  LPWSTR
              HostName:     LPWSTR
          }
          SubnetState:    DWORD (enum)
      }
      ReturnValue: DWORD
    """
    p = NDRParser(data)

    if not p.read_ptr():
        ret_val = p.read_dword()
        return None, ret_val

    info = {}

    # Fixed fields of DHCP_SUBNET_INFO
    info['address'] = p.read_ip()
    info['mask'], mask_int = p.read_ip_raw()
    info['cidr'] = bin(mask_int).count('1')

    # LPWSTR pointers (in fixed part)
    name_ref = p.read_ptr()
    comment_ref = p.read_ptr()

    # PrimaryHost fixed fields
    info['host_ip'] = p.read_ip()
    host_netbios_ref = p.read_ptr()
    host_hostname_ref = p.read_ptr()

    # SubnetState
    state = p.read_dword()
    info['state'] = {0: 'Enabled', 1: 'Disabled', 2: 'Switched'}.get(
        state, f'Unknown({state})'
    )

    # Deferred string data (in pointer order)
    info['name'] = p.read_cvstring() if name_ref else ''
    info['comment'] = p.read_cvstring() if comment_ref else ''
    info['host_netbios'] = p.read_cvstring() if host_netbios_ref else ''
    info['host_hostname'] = p.read_cvstring() if host_hostname_ref else ''

    ret_val = p.read_dword()
    return info, ret_val


def parse_enum_clients_response(data):
    """
    Parse R_DhcpEnumSubnetClients response.

    Response layout:
      ResumeHandle:  DWORD
      ClientInfo:    unique ptr → DHCP_CLIENT_INFO_ARRAY {
          NumElements: DWORD,
          Clients:     unique ptr → conformant array of
                       LPDHCP_CLIENT_INFO (pointers)
      }
      ClientsRead:   DWORD
      ClientsTotal:  DWORD
      ReturnValue:   DWORD

    Each DHCP_CLIENT_INFO (pointed to by array element):
      Fixed:
        ClientIpAddress:     DWORD
        SubnetMask:          DWORD
        ClientHardwareAddress:
          DataLength:        DWORD
          Data:              unique ptr ref
        ClientName:          unique ptr ref (LPWSTR)
        ClientComment:       unique ptr ref (LPWSTR)
        ClientLeaseExpires:
          dwLowDateTime:     DWORD
          dwHighDateTime:    DWORD
        OwnerHost:
          IpAddress:         DWORD
          NetBiosName:       unique ptr ref (LPWSTR)
          HostName:          unique ptr ref (LPWSTR)
      Deferred (in pointer order):
        HW Data bytes, ClientName, ClientComment,
        OwnerHost.NetBiosName, OwnerHost.HostName
    """
    p = NDRParser(data)
    resume = p.read_dword()
    clients = []

    if not p.read_ptr():  # ClientInfo array outer pointer is NULL (no clients)
        ret_val = 0
        if p.remaining() >= 12:
            clients_read = p.read_dword()
            clients_total = p.read_dword()
            ret_val = p.read_dword()
        elif p.remaining() >= 4:
            ret_val = p.read_dword()
        return clients, resume, ret_val

    num_elements = p.read_dword()

    if not p.read_ptr():  # Clients array inner pointer
        ret_val = 0
        if p.remaining() >= 12:
            clients_read = p.read_dword()
            clients_total = p.read_dword()
            ret_val = p.read_dword()
        elif p.remaining() >= 4:
            ret_val = p.read_dword()
        return clients, resume, ret_val

    # Conformant array max_count
    _ = p.read_dword()

    # Array of pointer referent IDs
    ptr_refs = [p.read_dword() for _ in range(num_elements)]

    # Parse each DHCP_CLIENT_INFO structure
    for i in range(num_elements):
        if ptr_refs[i] == 0:
            continue

        try:
            client = parse_single_client(p)
            clients.append(client)
        except Exception as e:
            print(f'    [!] Error parsing client {i}: {e}')
            break

    # Skip to trailer (may be misaligned if parsing failed)
    try:
        if len(data) >= 12:
            trailer = data[-12:]
            clients_read = struct.unpack_from('<I', trailer, 0)[0]
            clients_total = struct.unpack_from('<I', trailer, 4)[0]
            ret_val = struct.unpack_from('<I', trailer, 8)[0]
        elif len(data) >= 4:
            ret_val = struct.unpack_from('<I', data, len(data) - 4)[0]
        else:
            ret_val = 0
    except Exception:
        ret_val = 0

    return clients, resume, ret_val


def parse_single_client(p):
    """Parse a single DHCP_CLIENT_INFO from NDR stream."""
    client = {}

    # === FIXED PART ===
    client['ip'] = p.read_ip()
    client['mask'] = p.read_ip()

    # ClientHardwareAddress (DHCP_CLIENT_UID)
    hw_data_len = p.read_dword()
    hw_ptr = p.read_ptr()

    # ClientName, ClientComment (LPWSTR unique ptrs)
    name_ptr = p.read_ptr()
    comment_ptr = p.read_ptr()

    # ClientLeaseExpires (DATE_TIME)
    lease_low = p.read_dword()
    lease_high = p.read_dword()
    client['lease_expires'] = filetime_to_str(lease_low, lease_high)

    # OwnerHost (DHCP_HOST_INFO)
    client['owner_ip'] = p.read_ip()
    owner_nb_ptr = p.read_ptr()
    owner_hn_ptr = p.read_ptr()

    # === DEFERRED DATA (in pointer order) ===

    # 1. HW address bytes
    if hw_ptr and hw_data_len > 0:
        raw = p.read_conformant_bytes(hw_data_len)
        if len(raw) >= 6:
            client['mac'] = ':'.join(f'{b:02X}' for b in raw[:6])
        elif len(raw) > 0:
            client['mac'] = ':'.join(f'{b:02X}' for b in raw)
        else:
            client['mac'] = 'N/A'
    else:
        client['mac'] = 'N/A'

    # 2. ClientName
    client['name'] = p.read_cvstring() if name_ptr else ''

    # 3. ClientComment
    client['comment'] = p.read_cvstring() if comment_ptr else ''

    # 4. OwnerHost.NetBiosName
    client['owner_netbios'] = p.read_cvstring() if owner_nb_ptr else ''

    # 5. OwnerHost.HostName
    client['owner_hostname'] = p.read_cvstring() if owner_hn_ptr else ''

    return client


def filetime_to_str(low, high):
    """Convert Windows FILETIME to human-readable string."""
    timestamp = (high << 32) | low
    if timestamp == 0 or timestamp >= 0x7FFFFFFFFFFFFFFF:
        return 'Never'
    try:
        epoch_diff = 116444736000000000  # 1601-01-01 to 1970-01-01
        if timestamp > epoch_diff:
            from datetime import datetime, timezone
            unix_ts = (timestamp - epoch_diff) / 10_000_000
            dt = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
            return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except (ValueError, OSError, OverflowError):
        pass
    return 'Unknown'


def mac_vendor_prefix(mac):
    """Return first 3 octets (OUI) for vendor lookup reference."""
    parts = mac.split(':')
    if len(parts) >= 3:
        return f'{parts[0]}:{parts[1]}:{parts[2]}'
    return mac


# ============================================================
# Main DHCP Enumerator
# ============================================================

class DhcpDumper:
    def __init__(self, target, username='', password='', domain='',
                 lmhash='', nthash='', use_tcp=False):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.use_tcp = use_tcp
        self.dce = None

    def connect(self):
        """Establish authenticated RPC connection to DHCP server."""
        if self.use_tcp:
            self._connect_tcp()
        else:
            self._connect_pipe()

    def _connect_pipe(self):
        """Connect via SMB named pipe (\\PIPE\\dhcpserver)."""
        binding = f'ncacn_np:{self.target}[\\PIPE\\dhcpserver]'
        rpctransport = transport.DCERPCTransportFactory(binding)
        rpctransport.set_credentials(
            self.username, self.password, self.domain,
            self.lmhash, self.nthash
        )
        rpctransport.set_connect_timeout(10)

        self.dce = rpctransport.get_dce_rpc()
        self.dce.connect()
        self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        self.dce.bind(MSRPC_UUID_DHCPSRV)
        print(f'[+] Connected via \\\\{self.target}\\PIPE\\dhcpserver')

    def _connect_tcp(self):
        """Connect via TCP (dynamic port from EPM)."""
        try:
            binding = epm.hept_map(
                self.target, MSRPC_UUID_DHCPSRV,
                protocol='ncacn_ip_tcp'
            )
        except Exception as e:
            print(f'[-] EPM lookup failed: {e}')
            print('[*] Falling back to named pipe...')
            self._connect_pipe()
            return

        rpctransport = transport.DCERPCTransportFactory(binding)
        rpctransport.set_credentials(
            self.username, self.password, self.domain,
            self.lmhash, self.nthash
        )
        rpctransport.set_connect_timeout(10)

        self.dce = rpctransport.get_dce_rpc()
        self.dce.connect()
        self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        self.dce.bind(MSRPC_UUID_DHCPSRV)
        print(f'[+] Connected via TCP to {self.target}')

    def disconnect(self):
        if self.dce:
            try:
                self.dce.disconnect()
            except Exception:
                pass

    def enum_subnets(self):
        """R_DhcpEnumSubnets — enumerate all DHCP scopes."""
        all_subnets = []
        resume = 0

        while True:
            self.dce.call(OPNUM_ENUM_SUBNETS, build_enum_subnets(resume))
            resp = self.dce.recv()

            subnets, resume, ret_val = parse_enum_subnets_response(resp)
            all_subnets.extend(subnets)

            if ret_val == ERROR_MORE_DATA:
                continue
            break

        return all_subnets

    def get_subnet_info(self, subnet_ip):
        """R_DhcpGetSubnetInfo — get details for a specific scope."""
        self.dce.call(OPNUM_GET_SUBNET_INFO, build_get_subnet_info(subnet_ip))
        resp = self.dce.recv()
        info, ret_val = parse_get_subnet_info_response(resp)
        return info

    def enum_clients(self, subnet_ip):
        """R_DhcpEnumSubnetClients — enumerate all leases in a scope."""
        all_clients = []
        resume = 0

        while True:
            self.dce.call(
                OPNUM_ENUM_SUBNET_CLIENTS,
                build_enum_clients(subnet_ip, resume)
            )
            resp = self.dce.recv()

            clients, resume, ret_val = parse_enum_clients_response(resp)
            all_clients.extend(clients)

            if ret_val == ERROR_MORE_DATA:
                continue
            break

        return all_clients


# ============================================================
# Output Formatting
# ============================================================

def print_banner():
    print("""
    ╔══════════════════════════════════════════════╗
    ║  dhcp_dump.py — MS-DHCPM Remote Enumeration ║
    ║  First red team tool for this protocol       ║
    ╚══════════════════════════════════════════════╝
    """)


def print_subnet_info(info):
    state_icon = '●' if info['state'] == 'Enabled' else '○'
    name = info.get('name', '') or '(unnamed)'
    comment = info.get('comment', '')
    host = info.get('host_hostname', '') or info.get('host_netbios', '') or ''

    print(f"  {state_icon} {info['address']}/{info['cidr']}  "
          f"mask {info['mask']}  [{info['state']}]")
    print(f"    Name:    {name}")
    if comment:
        print(f"    Comment: {comment}")
    if host:
        print(f"    Server:  {host} ({info.get('host_ip', '')})")


def print_clients_table(clients):
    if not clients:
        print("    (no active leases)")
        return

    # Header
    print(f"    {'IP Address':<17} {'MAC Address':<19} "
          f"{'Hostname':<25} {'Lease Expires'}")
    print(f"    {'─' * 17} {'─' * 19} {'─' * 25} {'─' * 23}")

    for c in clients:
        name = c.get('name', '') or ''
        if len(name) > 24:
            name = name[:21] + '...'
        print(f"    {c['ip']:<17} {c['mac']:<19} "
              f"{name:<25} {c.get('lease_expires', '')}")


def print_summary(all_subnets_info, all_clients):
    """Print network topology summary."""
    print("\n" + "=" * 60)
    print("  NETWORK TOPOLOGY SUMMARY")
    print("=" * 60)

    total_clients = sum(len(c) for c in all_clients.values())
    enabled = sum(1 for s in all_subnets_info if s and s['state'] == 'Enabled')
    disabled = sum(1 for s in all_subnets_info if s and s['state'] != 'Enabled')

    print(f"\n  Subnets:  {len(all_subnets_info)} total "
          f"({enabled} enabled, {disabled} disabled)")
    print(f"  Clients:  {total_clients} active leases")

    # Unique MACs
    all_macs = set()
    for clients in all_clients.values():
        for c in clients:
            if c.get('mac', 'N/A') != 'N/A':
                all_macs.add(c['mac'])
    print(f"  Unique MACs: {len(all_macs)}")

    # Network ranges discovered
    print(f"\n  Discovered networks:")
    for info in all_subnets_info:
        if info:
            client_count = len(all_clients.get(info['address'], []))
            name = info.get('name', '') or ''
            print(f"    {info['address']}/{info['cidr']:<4} "
                  f"({client_count:>3} clients)  {name}")

    # OUI distribution
    oui_count = defaultdict(int)
    for clients in all_clients.values():
        for c in clients:
            mac = c.get('mac', 'N/A')
            if mac != 'N/A':
                oui_count[mac_vendor_prefix(mac)] += 1

    if oui_count:
        print(f"\n  MAC OUI distribution (top 10):")
        for oui, count in sorted(oui_count.items(),
                                  key=lambda x: x[1], reverse=True)[:10]:
            print(f"    {oui}  → {count} devices")

    print()


# ============================================================
# Entry Point
# ============================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description='MS-DHCPM Remote DHCP Enumeration Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -target 10.0.1.1 -u admin -p Password1 -d contoso.com
  %(prog)s -target 10.0.1.1 -u admin -H :a1b2c3d4e5f6 -d contoso.com
  %(prog)s -target 10.0.1.1 -u admin -p Password1 -d contoso.com -tcp
  %(prog)s -target 10.0.1.1 -u admin -p Password1 -d contoso.com -subnets-only

Required access: DHCP Users or DHCP Administrators group membership
        """
    )
    parser.add_argument('-target', required=True,
                        help='DHCP server IP or hostname')
    parser.add_argument('-u', '-username', dest='username', default='',
                        help='Username for authentication')
    parser.add_argument('-p', '-password', dest='password', default='',
                        help='Password for authentication')
    parser.add_argument('-d', '-domain', dest='domain', default='',
                        help='Domain name')
    parser.add_argument('-H', '-hashes', dest='hashes', default='',
                        help='NTLM hash (format LM:NT or :NT)')
    parser.add_argument('-tcp', action='store_true',
                        help='Use TCP transport instead of named pipe')
    parser.add_argument('-subnets-only', action='store_true',
                        help='Only enumerate subnets, skip client leases')
    parser.add_argument('-subnet', default=None,
                        help='Enumerate clients for a specific subnet only')
    parser.add_argument('-o', '-output', dest='output', default=None,
                        help='Output results to CSV file')

    return parser.parse_args()


def main():
    print_banner()
    args = parse_args()

    # Parse hashes
    lmhash = ''
    nthash = ''
    if args.hashes:
        if ':' in args.hashes:
            lmhash, nthash = args.hashes.split(':')
        else:
            nthash = args.hashes

    dumper = DhcpDumper(
        target=args.target,
        username=args.username,
        password=args.password,
        domain=args.domain,
        lmhash=lmhash,
        nthash=nthash,
        use_tcp=args.tcp
    )

    try:
        # Connect
        print(f'[*] Connecting to {args.target}...')
        dumper.connect()
        print()

        # Enumerate subnets
        print('[*] Enumerating DHCP subnets (R_DhcpEnumSubnets)...')
        subnet_ips = dumper.enum_subnets()

        if not subnet_ips:
            print('[-] No subnets found (empty response or access denied)')
            return

        print(f'[+] Found {len(subnet_ips)} subnet(s)\n')

        # Get subnet details
        all_subnets_info = []
        all_clients = {}

        target_subnets = subnet_ips
        if args.subnet:
            if args.subnet in subnet_ips:
                target_subnets = [args.subnet]
            else:
                print(f'[-] Subnet {args.subnet} not found in DHCP scopes')
                print(f'[*] Available: {", ".join(subnet_ips)}')
                return

        for subnet_ip in target_subnets:
            print(f'[*] Scope: {subnet_ip}')

            # Get subnet info
            info = dumper.get_subnet_info(subnet_ip)
            all_subnets_info.append(info)

            if info:
                print_subnet_info(info)
            else:
                print(f'  [!] Could not retrieve info for {subnet_ip}')

            # Enumerate clients
            if not args.subnets_only:
                print(f'    [*] Enumerating leases '
                      f'(R_DhcpEnumSubnetClients)...')
                try:
                    clients = dumper.enum_clients(subnet_ip)
                    all_clients[subnet_ip] = clients
                    print(f'    [+] {len(clients)} active lease(s)')
                    print_clients_table(clients)
                except DCERPCException as e:
                    print(f'    [-] Error: {e}')
                    all_clients[subnet_ip] = []
                except Exception as e:
                    print(f'    [-] Parse error: {e}')
                    all_clients[subnet_ip] = []

            print()

        # Summary
        print_summary(all_subnets_info, all_clients)

        # CSV export
        if args.output and all_clients:
            export_csv(args.output, all_subnets_info, all_clients)

    except DCERPCException as e:
        error_str = str(e).lower()
        if 'access_denied' in error_str or 'rpc_s_access_denied' in error_str:
            print('\n[-] ACCESS DENIED')
            print('    Required: membership in DHCP Users or '
                  'DHCP Administrators group')
            print('    Check with: net localgroup "DHCP Users" '
                  '/domain')
        else:
            print(f'\n[-] DCE/RPC error: {e}')
    except ConnectionRefusedError:
        print(f'[-] Connection refused to {args.target}')
        print('    Verify port 445 (SMB) or 135 (RPC) is open')
    except socket.timeout:
        print(f'[-] Timeout connecting to {args.target}')
    except Exception as e:
        print(f'[-] Error: {e}')
        import traceback
        traceback.print_exc()
    finally:
        dumper.disconnect()


def export_csv(filepath, subnets_info, all_clients):
    """Export results to CSV."""
    try:
        with open(filepath, 'w') as f:
            f.write('Subnet,SubnetMask,CIDR,ScopeName,State,'
                    'ClientIP,ClientMAC,ClientHostname,'
                    'LeaseExpires,OwnerServer\n')

            for info in subnets_info:
                if not info:
                    continue
                subnet = info['address']
                clients = all_clients.get(subnet, [])

                if not clients:
                    f.write(f"{subnet},{info['mask']},{info['cidr']},"
                            f"{info.get('name', '')},"
                            f"{info['state']},,,,\n")
                    continue

                for c in clients:
                    f.write(f"{subnet},{info['mask']},{info['cidr']},"
                            f"{info.get('name', '')},"
                            f"{info['state']},"
                            f"{c['ip']},{c['mac']},"
                            f"{c.get('name', '')},"
                            f"{c.get('lease_expires', '')},"
                            f"{c.get('owner_hostname', '')}\n")

        print(f'[+] Results exported to {filepath}')
    except Exception as e:
        print(f'[-] CSV export error: {e}')


if __name__ == '__main__':
    main()
