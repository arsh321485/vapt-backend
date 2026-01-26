"""
Utility functions for scope management:
- IP address classification (internal vs external)
- URL validation
- File parsing (Excel, CSV, Word, Text)
"""
import ipaddress
import re
from typing import List, Dict, Tuple, Optional
from urllib.parse import urlparse


def is_internal_ip(ip_str: str) -> bool:
    """
    Check if an IP address is internal (RFC 1918 and special ranges).
    
    Internal IP ranges:
    - 10.0.0.0/8 (10.0.0.0 - 10.255.255.255)
    - 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    - 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)
    - 100.64.0.0/10 (100.64.0.0 - 100.127.255.255) - Carrier-Grade NAT
    - 169.254.0.0/16 (169.254.0.0 - 169.254.255.255) - Link-local
    - 127.0.0.0/8 (127.0.0.0 - 127.255.255.255) - Loopback
    
    Args:
        ip_str: IP address string (IPv4 or IPv6)
    
    Returns:
        True if internal, False if external or invalid
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        
        # IPv4 internal ranges
        if ip.version == 4:
            # RFC 1918 private ranges
            if ip.is_private:
                return True
            
            # Special internal ranges
            internal_ranges = [
                ipaddress.ip_network('100.64.0.0/10'),  # Carrier-Grade NAT
                ipaddress.ip_network('169.254.0.0/16'),  # Link-local
                ipaddress.ip_network('127.0.0.0/8'),     # Loopback
            ]
            
            for network in internal_ranges:
                if ip in network:
                    return True
            
            # Check if it's 0.0.0.0 (default/unknown route)
            if ip_str.strip() == '0.0.0.0':
                return True
            
            return False
        
        # IPv6 internal ranges
        elif ip.version == 6:
            # Unique Local Address (ULA) - fc00::/7
            if ip.is_private:
                return True
            
            # Link-local IPv6 - fe80::/10
            link_local = ipaddress.ip_network('fe80::/10')
            if ip in link_local:
                return True
            
            return False
        
        return False
    
    except (ValueError, ipaddress.AddressValueError):
        return False


def is_valid_ip(ip_str: str) -> bool:
    """
    Check if a string is a valid IP address (IPv4 or IPv6).
    
    Args:
        ip_str: String to validate
    
    Returns:
        True if valid IP, False otherwise
    """
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except (ValueError, ipaddress.AddressValueError):
        return False


def is_valid_subnet(subnet_str: str) -> bool:
    """
    Check if a string is a valid subnet (CIDR notation).
    
    Args:
        subnet_str: String to validate (e.g., "192.168.1.0/24")
    
    Returns:
        True if valid subnet, False otherwise
    """
    try:
        ipaddress.ip_network(subnet_str.strip(), strict=False)
        return True
    except (ValueError, ipaddress.AddressValueError):
        return False


def is_internal_subnet(subnet_str: str) -> bool:
    """
    Check if a subnet contains internal IPs.
    
    Args:
        subnet_str: Subnet in CIDR notation (e.g., "192.168.1.0/24")
    
    Returns:
        True if subnet contains internal IPs, False if external
    """
    try:
        network = ipaddress.ip_network(subnet_str.strip(), strict=False)
        
        # Check if the network itself is private (RFC 1918)
        if network.is_private:
            return True
        
        # Check if any IP in the subnet would be internal
        # For efficiency, check the network address and a sample
        network_addr = network.network_address
        
        # Check network address
        if is_internal_ip(str(network_addr)):
            return True
        
        # For small subnets, check a few sample IPs
        if network.num_addresses <= 256:
            # Check first few host IPs
            for i, ip in enumerate(network.hosts()):
                if i >= 5:  # Check first 5 IPs
                    break
                if is_internal_ip(str(ip)):
                    return True
        
        return False
    
    except (ValueError, ipaddress.AddressValueError):
        return False


def get_subnet_count(subnet_str: str) -> int:
    """
    Get the number of host IPs in a subnet (excluding network and broadcast).
    
    Args:
        subnet_str: Subnet in CIDR notation (e.g., "192.168.1.0/24")
    
    Returns:
        Number of host IPs in the subnet
    """
    try:
        network = ipaddress.ip_network(subnet_str.strip(), strict=False)
        # Return number of host addresses (excluding network and broadcast)
        return network.num_addresses - 2 if network.num_addresses > 2 else network.num_addresses
    except (ValueError, ipaddress.AddressValueError):
        return 0


def expand_subnet(subnet_str: str) -> List[str]:
    """
    Expand a subnet (CIDR notation) into individual IP addresses.
    Returns clean IP addresses without CIDR notation.
    
    Args:
        subnet_str: Subnet in CIDR notation (e.g., "192.168.1.0/24")
    
    Returns:
        List of IP addresses in the subnet (without /32 suffix)
    """
    try:
        network = ipaddress.ip_network(subnet_str.strip(), strict=False)
        # Limit expansion to prevent memory issues with large subnets
        # For /24 and smaller, expand all IPs
        # For larger subnets, return the network representation
        if network.prefixlen <= 24:
            # Return clean IP addresses without any CIDR notation
            return [str(ip) for ip in network.hosts()]  # Excludes network and broadcast
        else:
            # For larger subnets, return empty list (don't expand)
            # Or return the network address as a single IP
            if network.num_addresses == 1:
                return [str(network.network_address)]
            return []
    except (ValueError, ipaddress.AddressValueError):
        return []


def is_mobile_url(url_str: str) -> bool:
    """
    Check if a URL is a mobile URL.
    
    Mobile URL patterns:
    - mobile.example.com
    - m.example.com
    - www.mobile.example.com
    - app.example.com (mobile apps)
    - api.mobile.example.com
    - Play Store URLs (play.google.com/store/apps/...)
    - Apple Store URLs (apps.apple.com/..., itunes.apple.com/...)
    
    Args:
        url_str: URL string to check
    
    Returns:
        True if mobile URL, False otherwise
    """
    url_str_lower = url_str.strip().lower()
    original_url = url_str_lower
    
    # Check for Play Store and Apple Store URLs (need full URL with path)
    store_patterns = [
        r'play\.google\.com',  # Play Store
        r'apps\.apple\.com',  # Apple App Store
        r'itunes\.apple\.com',  # iTunes/App Store
    ]
    
    for pattern in store_patterns:
        if re.search(pattern, original_url):
            return True
    
    # Remove protocol if present for domain-based checks
    if url_str_lower.startswith(('http://', 'https://')):
        url_str_lower = url_str_lower.split('://', 1)[1]
    
    # Extract domain (remove path and query)
    domain = url_str_lower.split('/')[0]
    
    # Mobile URL patterns (domain-based)
    mobile_patterns = [
        r'^m\.',  # m.example.com
        r'^mobile\.',  # mobile.example.com
        r'\.m\.',  # www.m.example.com
        r'\.mobile\.',  # www.mobile.example.com
        r'^app\.',  # app.example.com
        r'\.app\.',  # www.app.example.com
        r'^api\.mobile\.',  # api.mobile.example.com
        r'^mobile-api\.',  # mobile-api.example.com
    ]
    
    for pattern in mobile_patterns:
        if re.search(pattern, domain):
            return True
    
    return False


def is_valid_url(url_str: str) -> bool:
    """
    Check if a string is a valid URL.
    
    Args:
        url_str: String to validate
    
    Returns:
        True if valid URL, False otherwise
    """
    url_str = url_str.strip()
    
    # Basic URL pattern check
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE
    )
    
    # Also allow URLs without protocol (will add http://)
    url_without_protocol = re.compile(
        r'^(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)?$', re.IGNORECASE
    )
    
    if url_pattern.match(url_str) or url_without_protocol.match(url_str):
        try:
            # Try parsing with urlparse for additional validation
            parsed = urlparse(url_str if url_str.startswith(('http://', 'https://')) else f'http://{url_str}')
            return bool(parsed.netloc)
        except Exception:
            return False
    
    return False


def normalize_url(url_str: str) -> str:
    """
    Normalize URL by adding protocol if missing.
    
    Args:
        url_str: URL string
    
    Returns:
        Normalized URL with protocol
    """
    url_str = url_str.strip()
    if not url_str.startswith(('http://', 'https://')):
        return f'https://{url_str}'
    return url_str


def classify_target(target: str) -> Optional[Tuple[str, str]]:
    """
    Classify a target and return ONLY one of these 4 types:
    - internal_ip: Internal IP addresses or internal subnets
    - external_ip: External IP addresses or external subnets
    - mobile_url: Mobile URLs (including Play Store, Apple Store, m.*, mobile.*, etc.)
    - web_url: Web URLs
    
    Subnets are classified as internal_ip or external_ip based on their IP range.
    All other inputs are rejected (returns None).
    
    Args:
        target: Target string (IP, URL, or subnet)
    
    Returns:
        Tuple of (target_type, normalized_value) or None if invalid/not accepted
    """
    target = target.strip()
    
    if not target:
        return None
    
    # Remove /32 suffix if present (individual IPs shouldn't have CIDR notation)
    clean_target = target
    if target.endswith('/32'):
        clean_target = target.replace('/32', '')
    
    # Check if it's a subnet (must have CIDR notation with /, and not /32)
    # Individual IPs without CIDR notation should be checked as IPs, not subnets
    if '/' in target and not target.endswith('/32'):
        if is_valid_subnet(target):
            # Classify subnet as internal or external based on IP range
            if is_internal_subnet(target):
                return ('internal_ip', target)  # Subnet with internal IPs
            else:
                return ('external_ip', target)  # Subnet with external IPs
    
    # Check if it's a valid IP (use clean target without /32)
    if is_valid_ip(clean_target):
        if is_internal_ip(clean_target):
            return ('internal_ip', clean_target)  # Return clean IP without /32
        else:
            return ('external_ip', clean_target)  # Return clean IP without /32
    
    # Check if it's a valid URL
    if is_valid_url(target):
        normalized = normalize_url(target)
        # Check if it's a mobile URL
        if is_mobile_url(normalized):
            return ('mobile_url', normalized)
        else:
            return ('web_url', normalized)
    
    return None


def extract_targets_from_text(text: str, expand_subnets: bool = True) -> List[Dict[str, any]]:
    """
    Extract and classify targets from text (one per line).
    Only accepts: Internal IP, External IP, Mobile URL, and Web URL.
    Subnets are classified as internal_ip or external_ip based on their IP range.
    All other inputs are automatically rejected and not included in the results.
    
    Args:
        text: Text containing targets (one per line)
        expand_subnets: If True, expand subnets into individual IPs. If False, keep as subnet with count.
    
    Returns:
        List of dicts with 'target_type', 'target_value', and optionally 'subnet_count'.
        Only contains valid targets (internal_ip, external_ip, mobile_url, web_url).
    """
    targets = []
    seen = set()  # To avoid duplicates
    
    for line in text.split('\n'):
        line = line.strip()
        if not line:
            continue
        
        # Remove comments (lines starting with #)
        if line.startswith('#'):
            continue
        
        # Check if it's a subnet first (must have CIDR notation with /, and not /32)
        if '/' in line and not line.endswith('/32') and is_valid_subnet(line):
            if expand_subnets:
                # Expand subnet into individual IPs
                expanded_ips = expand_subnet(line)
                for ip in expanded_ips:
                    # Clean IP address - remove any /32 or CIDR notation
                    clean_ip = str(ip).split('/')[0] if '/' in str(ip) else str(ip)
                    if clean_ip not in seen:
                        seen.add(clean_ip)
                        # Classify each IP (should return clean IP without /32)
                        ip_result = classify_target(clean_ip)
                        if ip_result:
                            ip_type, ip_value = ip_result
                            # Ensure no /32 suffix for individual IPs
                            if '/' in ip_value:
                                ip_value = ip_value.split('/')[0]
                            targets.append({
                                'target_type': ip_type,
                                'target_value': ip_value,
                                # NO subnet_count for individual IPs
                            })
            else:
                # Keep as subnet with classification and count
                if line not in seen:
                    seen.add(line)
                    # Classify subnet
                    subnet_result = classify_target(line)
                    if subnet_result:
                        subnet_type, subnet_value = subnet_result
                        subnet_count = get_subnet_count(line)
                        targets.append({
                            'target_type': subnet_type,  # internal_ip or external_ip based on subnet range
                            'target_value': subnet_value,
                            'subnet_count': subnet_count
                        })
            continue
        
        # Try to classify the target
        result = classify_target(line)
        if result:
            target_type, target_value = result
            # Clean target_value - remove /32 if it's an individual IP
            # (Individual IPs shouldn't have CIDR notation)
            if '/' in target_value and not is_valid_subnet(target_value):
                # If it's /32, it's just a single IP, remove the /32
                if target_value.endswith('/32'):
                    target_value = target_value.replace('/32', '')
            
            # Use normalized value as key for deduplication
            if target_value not in seen:
                seen.add(target_value)
                target_dict = {
                    'target_type': target_type,
                    'target_value': target_value
                }
                # Add subnet_count ONLY if it's actually a subnet (has CIDR notation, not /32)
                # Individual IPs should NOT have subnet_count
                if is_valid_subnet(target_value) and '/' in target_value and not target_value.endswith('/32'):
                    target_dict['subnet_count'] = get_subnet_count(target_value)
                targets.append(target_dict)
    
    return targets
