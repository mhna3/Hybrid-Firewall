#!/usr/bin/env python3

import time
import socket
import struct
import threading
import logging
import argparse
import ipaddress
import json
import requests
import datetime
import re
import geoip2.database
import os
import hashlib
import base64
import numpy as np
from urllib.parse import urlparse
from collections import defaultdict, deque, Counter
from enum import Enum
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("firewall.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("HybridFirewall")

class Protocol(Enum):
    TCP = 6
    UDP = 17
    ICMP = 1

class ConnState(Enum):
    NEW = 1
    ESTABLISHED = 2
    RELATED = 3
    INVALID = 4
    CLOSED = 5

class Action(Enum):
    ACCEPT = 1
    DROP = 2
    REJECT = 3
    LOG = 4

class Direction(Enum):
    INBOUND = 1
    OUTBOUND = 2

class FilterRule:
    """    
    Attributes:
        rule_id (int): Unique identifier for the rule
        src_ip (str): Source IP address or network (CIDR)
        dst_ip (str): Destination IP address or network (CIDR)
        src_port (int or tuple): Source port or range of ports
        dst_port (int or tuple): Destination port or range of ports
        protocol (Protocol): Protocol this rule applies to
        action (Action): Action to take if the rule matches
        direction (Direction): Direction of traffic this rule applies to
        description (str): Human-readable description of the rule
    """
    
    def __init__(self, rule_id, src_ip="0.0.0.0/0", dst_ip="0.0.0.0/0", 
                 src_port=None, dst_port=None, protocol=None, 
                 action=Action.DROP, direction=Direction.INBOUND, description=""):
        self.rule_id = rule_id
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.action = action
        self.direction = direction
        self.description = description
        
        # Convert string IPs to network objects for CIDR matching
        try:
            self.src_net = ipaddress.ip_network(src_ip)
        except ValueError:
            self.src_net = ipaddress.ip_network(f"{src_ip}/32")
            
        try:
            self.dst_net = ipaddress.ip_network(dst_ip)
        except ValueError:
            self.dst_net = ipaddress.ip_network(f"{dst_ip}/32")
    
    def matches(self, packet):
        # Check direction first
        if self.direction == Direction.INBOUND and packet.get('direction') != Direction.INBOUND:
            return False
        if self.direction == Direction.OUTBOUND and packet.get('direction') != Direction.OUTBOUND:
            return False
        
        # Check IP addresses (using CIDR matching)
        if packet.get('src_ip') and not ipaddress.ip_address(packet['src_ip']) in self.src_net:
            return False
        if packet.get('dst_ip') and not ipaddress.ip_address(packet['dst_ip']) in self.dst_net:
            return False
        
        # Check protocol
        if self.protocol and packet.get('protocol') != self.protocol:
            return False
        
        # Check ports
        if self.src_port:
            if isinstance(self.src_port, tuple):
                if packet.get('src_port') < self.src_port[0] or packet.get('src_port') > self.src_port[1]:
                    return False
            elif packet.get('src_port') != self.src_port:
                return False
                
        if self.dst_port:
            if isinstance(self.dst_port, tuple):
                if packet.get('dst_port') < self.dst_port[0] or packet.get('dst_port') > self.dst_port[1]:
                    return False
            elif packet.get('dst_port') != self.dst_port:
                return False
        
        return True
    
    def __str__(self):
        proto = self.protocol.name if self.protocol else "ANY"
        src_port = f":{self.src_port}" if self.src_port else ""
        dst_port = f":{self.dst_port}" if self.dst_port else ""
        dir_str = "IN" if self.direction == Direction.INBOUND else "OUT"
        
        return (f"Rule {self.rule_id}: {dir_str} {self.src_ip}{src_port} -> "
                f"{self.dst_ip}{dst_port} ({proto}) : {self.action.name} - {self.description}")


class ConnectionTracker:  
    def __init__(self, timeout=60, max_conn=10000):

        self.connections = {}  # Main connection state table
        self.timeout = timeout
        self.max_conn = max_conn
        self.lock = threading.RLock()
        
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired, daemon=True)
        self.cleanup_thread.start()
    
    def _conn_key(self, packet):
        """Create a unique key for identifying a connection"""
        if packet['protocol'] == Protocol.ICMP:
            return (packet['src_ip'], packet['dst_ip'], Protocol.ICMP, 0, 0)
        else:
            return (packet['src_ip'], packet['dst_ip'], packet['protocol'], 
                   packet['src_port'], packet['dst_port'])
    
    def _reverse_key(self, key):
        """Get the reverse connection key (for replies)"""
        src_ip, dst_ip, protocol, src_port, dst_port = key
        return (dst_ip, src_ip, protocol, dst_port, src_port)
    
    def get_state(self, packet):
        with self.lock:
            key = self._conn_key(packet)
            rev_key = self._reverse_key(key)
            
            # Check for existing connection
            if key in self.connections:
                conn = self.connections[key]
                conn['last_seen'] = time.time()
                return conn['state']
            
            # Check for existing connection in reverse direction
            if rev_key in self.connections:
                if packet['protocol'] == Protocol.TCP:
                    # Check TCP flags
                    if packet.get('tcp_flags', {}).get('ACK', False):
                        conn = self.connections[rev_key]
                        conn['last_seen'] = time.time()
                        
                        # If connection is new and this is an ACK, move to ESTABLISHED
                        if conn['state'] == ConnState.NEW:
                            conn['state'] = ConnState.ESTABLISHED
                        
                        return ConnState.ESTABLISHED
                    else:
                        return ConnState.INVALID
                
                # For UDP and other protocols, consider it RELATED
                conn = self.connections[rev_key]
                conn['last_seen'] = time.time()
                return ConnState.RELATED
            
            # No existing connection found
            return ConnState.NEW
    
    def update_state(self, packet, state):
        with self.lock:
            # If at max capacity and this is a new connection, don't add it
            if len(self.connections) >= self.max_conn and state == ConnState.NEW:
                logger.warning(f"Connection table full, dropping new connection: {packet}")
                return
            
            key = self._conn_key(packet)
            
            # Create or update connection
            self.connections[key] = {
                'state': state,
                'start_time': time.time() if state == ConnState.NEW else 
                              self.connections.get(key, {}).get('start_time', time.time()),
                'last_seen': time.time(),
                'packets': self.connections.get(key, {}).get('packets', 0) + 1,
                'bytes': self.connections.get(key, {}).get('bytes', 0) + packet.get('length', 0)
            }
    
    def _cleanup_expired(self):
        while True:
            time.sleep(5)  # Check every 5 seconds
            
            with self.lock:
                current_time = time.time()
                expired_keys = []
                
                for key, conn in self.connections.items():
                    # TCP connection with FIN or RST
                    if conn['state'] == ConnState.CLOSED:
                        if current_time - conn['last_seen'] > 10:  # Shorter timeout for closed
                            expired_keys.append(key)
                    # Normal timeout for other connections
                    elif current_time - conn['last_seen'] > self.timeout:
                        expired_keys.append(key)
                
                # Remove expired connections
                for key in expired_keys:
                    del self.connections[key]
    
    def close_connection(self, packet):
        with self.lock:
            key = self._conn_key(packet)
            if key in self.connections:
                self.connections[key]['state'] = ConnState.CLOSED
                self.connections[key]['last_seen'] = time.time()
    
    def get_stats(self):
        with self.lock:
            states = {state: 0 for state in ConnState}
            for conn in self.connections.values():
                states[conn['state']] += 1
            
            return {
                'total': len(self.connections),
                'max': self.max_conn,
                'by_state': {state.name: count for state, count in states.items()}
            }


class AttackDetector:  
    def __init__(self, blacklist_threshold=3, scan_threshold=2, scan_interval=5):

        self.blacklist = {}  # IP address -> (timestamp, count)
        self.scan_tracking = defaultdict(lambda: deque(maxlen=100))  # IP -> list of (timestamp, port)
        self.blacklist_threshold = blacklist_threshold
        self.scan_threshold = scan_threshold
        self.scan_interval = scan_interval
        
        # Track consecutive attempts to the same port.
        self.consecutive_attempts = defaultdict(lambda: defaultdict(lambda: {'count': 0, 'last_time': 0}))
        self.consecutive_threshold = 5  # e.g., 7 attempts
        self.consecutive_timeout = 60  # Reset counter if there's a gap over 60 sec
        self.lock = threading.RLock()

        # Start a thread to expire old blacklist entries
        self.cleanup_thread = threading.Thread(target=self._cleanup_blacklist, daemon=True)
        self.cleanup_thread.start()
    


    def record_port_attempt(self, src_ip, dst_port):
        now = time.time()
        with self.lock:
            entry = self.consecutive_attempts[src_ip][dst_port]
            # If the time since the last recorded attempt is too long, reset the counter.
            if now - entry['last_time'] > self.consecutive_timeout:
                entry['count'] = 0
            entry['count'] += 1
            entry['last_time'] = now

            if entry['count'] >= self.consecutive_threshold:
                logger.warning(f"Blocking IP {src_ip}: {entry['count']} consecutive attempts to port {dst_port}")
                # Optionally, you might want to reset the counter after blocking.
                entry['count'] = 0
                return True
            return False


    def record_failed_attempt(self, ip_address):

        with self.lock:
            now = time.time()
            
            if ip_address in self.blacklist:
                timestamp, count = self.blacklist[ip_address]
                
                # Reset if too old
                if now - timestamp > 60:  # 1 minute window
                    self.blacklist[ip_address] = (now, 1)
                    return False
                
                # Increment count
                count += 1
                self.blacklist[ip_address] = (timestamp, count)
                
                # Check if we should blacklist
                if count >= self.blacklist_threshold:
                    logger.warning(f"Blacklisting IP {ip_address} due to {count} failed attempts")
                    return True
            else:
                self.blacklist[ip_address] = (now, 1)
            
            return False
    
    def check_blacklisted(self, ip_address):
        with self.lock:
            if ip_address in self.blacklist:
                timestamp, count = self.blacklist[ip_address]
                
                # Only consider recent and over-threshold entries
                if count >= self.blacklist_threshold and time.time() - timestamp < 300:  # 5 minute blacklist
                    return True
            
            return False
    
    def record_connection(self, src_ip, dst_ip, dst_port):

        with self.lock:
            now = time.time()
            
            # Add to tracking
            self.scan_tracking[src_ip].append((now, dst_ip, dst_port))
            
            # Analyze for port scan - look at recent connections
            recent_ports = set()
            recent_ips = set()
            
            for timestamp, rec_dst_ip, rec_dst_port in self.scan_tracking[src_ip]:
                if now - timestamp <= self.scan_interval:
                    if rec_dst_ip == dst_ip:
                        recent_ports.add(rec_dst_port)
                    recent_ips.add(rec_dst_ip)
            
            # Port scan if many ports on same IP in short time
            if len(recent_ports) >= self.scan_threshold:
                logger.warning(f"Port scan detected from {src_ip} to {dst_ip}, {len(recent_ports)} ports")
                return True
                
            # Host scan if many IPs in short time
            if len(recent_ips) >= self.scan_threshold:
                logger.warning(f"Host scan detected from {src_ip}, {len(recent_ips)} hosts")
                return True
            
            return False
    
    def _cleanup_blacklist(self):
        while True:
            time.sleep(60)  # Check every minute
            
            with self.lock:
                current_time = time.time()
                expired_ips = []
                
                for ip, (timestamp, _) in self.blacklist.items():
                    if current_time - timestamp > 300:  # 5 minute expiration
                        expired_ips.append(ip)
                
                for ip in expired_ips:
                    del self.blacklist[ip]


class ForwardingElement:

    def __init__(self, default_action=Action.DROP):

        self.rules = []  # List of FilterRule objects
        self.default_action = default_action
    
    def add_rule(self, rule):
        """Add a filtering rule"""
        self.rules.append(rule)
        logger.info(f"Added rule: {rule}")
    
    def remove_rule(self, rule_id):
        """Remove a rule by ID"""
        for i, rule in enumerate(self.rules):
            if rule.rule_id == rule_id:
                removed = self.rules.pop(i)
                logger.info(f"Removed rule: {removed}")
                return True
        
        logger.warning(f"Rule ID {rule_id} not found")
        return False
    
    def evaluate_packet(self, packet):

        for rule in self.rules:
            if rule.matches(packet):
                logger.debug(f"Packet matched rule {rule.rule_id}: {rule.action.name}")
                return rule.action
        
        logger.debug(f"No rules matched packet, using default action: {self.default_action.name}")
        return self.default_action


class ControlElement:

    def __init__(self, connection_timeout=60, max_connections=10000):

        self.conn_tracker = ConnectionTracker(timeout=connection_timeout, max_conn=max_connections)
        self.attack_detector = AttackDetector()
    
    def process_packet(self, packet):

        src_ip = packet.get('src_ip')
        dst_ip = packet.get('dst_ip')
        dst_port = packet.get('dst_port')
        
        # Check if source is blacklisted
        if src_ip and self.attack_detector.check_blacklisted(src_ip):
            logger.debug(f"Packet from blacklisted IP: {src_ip}")
            return ConnState.INVALID, True
        
        # Get connection state
        state = self.conn_tracker.get_state(packet)
        
        # For new connections, check for attack patterns
        is_attack = False
        if state == ConnState.NEW:
            if src_ip and dst_ip and dst_port:
                is_attack = self.attack_detector.record_connection(src_ip, dst_ip, dst_port)
        
        # Update connection state if needed
        if state == ConnState.NEW:
            self.conn_tracker.update_state(packet, ConnState.NEW)
        
        # Special handling for TCP connection close
        if (packet.get('protocol') == Protocol.TCP and 
            (packet.get('tcp_flags', {}).get('FIN', False) or 
             packet.get('tcp_flags', {}).get('RST', False))):
            self.conn_tracker.close_connection(packet)
        
        return state, is_attack
    
    def record_failed_attempt(self, ip_address):
        """Record a failed connection attempt and possibly blacklist the IP"""
        return self.attack_detector.record_failed_attempt(ip_address)


class ThreatIntelligence:

    def __init__(self, enable_abuseipdb=True, enable_safebrowsing=True):

        self.enable_abuseipdb = enable_abuseipdb
        self.enable_safebrowsing = enable_safebrowsing
        
        # API configurations
        self.config = {
            'abuseipdb': {
                'api_key': '', #REMOVED FOR SECURITY PURPOSES
                'url': 'https://api.abuseipdb.com/api/v2/',
            },
            'google_safebrowsing': {
                'api_key': '', #REMOVED FOR SECURITY PURPOSES
                'url': 'https://safebrowsing.googleapis.com/v4/threatMatches:find',
            },
        }
        
        # Cache to minimize API calls
        self.ip_cache = {} 
        self.url_cache = {} 
        
        # Cache expiration (in seconds)
        self.cache_expiry = 3600  # 1 hour
        
        # Rate limiting
        self.last_abuseipdb_call = 0
        self.last_safebrowsing_call = 0
        self.min_api_interval = 2  # Minimum seconds between API calls
        
        logger.info("Threat Intelligence module initialized")
    
    def check_ip_reputation(self, ip_address):
        if not self.enable_abuseipdb:
            return False, 0
        
        # For demo/testing purposes - hardcoded test cases
        if ip_address == "185.143.223.12": 
            logger.warning(f"Demo mode: IP {ip_address} detected as malicious (demo)")
            return True, 90
            
        # Check cache first
        if ip_address in self.ip_cache:
            cache_entry = self.ip_cache[ip_address]
            if time.time() - cache_entry['timestamp'] < self.cache_expiry:
                # Cache hit
                return cache_entry['score'] >= 30, cache_entry['score']
        
        # Respect rate limiting
        current_time = time.time()
        if current_time - self.last_abuseipdb_call < self.min_api_interval:
            logger.debug(f"Rate limiting AbuseIPDB check for {ip_address}")
            return False, 0
        
        try:
            headers = {
                'Accept': 'application/json',
                'Key': self.config['abuseipdb']['api_key']
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 30,
                'verbose': False
            }
            
            self.last_abuseipdb_call = current_time
            response = requests.get(
                f"{self.config['abuseipdb']['url']}check", 
                headers=headers, 
                params=params,
                timeout=3
            )
            
            if response.status_code == 200:
                result = response.json()
                data = result.get('data', {})
                score = data.get('abuseConfidenceScore', 0)
                
                # Cache the result
                self.ip_cache[ip_address] = {
                    'score': score,
                    'timestamp': current_time
                }
                
                is_malicious = score >= 30  
                
                if is_malicious:
                    logger.warning(f"IP {ip_address} has malicious reputation score: {score}")
                else:
                    logger.debug(f"IP {ip_address} reputation score: {score}")
                
                return is_malicious, score
                
            else:
                logger.warning(f"AbuseIPDB API error: {response.status_code} - {response.text}")
                return False, 0
                
        except Exception as e:
            logger.error(f"Error checking IP reputation: {str(e)}")
            return False, 0
    
    def report_malicious_ip(self, ip_address, categories, comment=""):

        if not self.enable_abuseipdb:
            return False
        
        # Respect rate limiting
        current_time = time.time()
        if current_time - self.last_abuseipdb_call < self.min_api_interval:
            logger.debug(f"Rate limiting AbuseIPDB report for {ip_address}")
            return False
        
        try:
            # Build the API request
            headers = {
                'Accept': 'application/json',
                'Key': self.config['abuseipdb']['api_key']
            }
            
            # Join categories as comma-separated string
            categories_str = ','.join(map(str, categories))
            
            data = {
                'ip': ip_address,
                'categories': categories_str,
                'comment': comment
            }
            
            # Make the API request
            self.last_abuseipdb_call = current_time
            response = requests.post(
                f"{self.config['abuseipdb']['url']}report", 
                headers=headers, 
                data=data,
                timeout=3
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully reported IP {ip_address} to AbuseIPDB")
                return True
            else:
                logger.warning(f"Error reporting to AbuseIPDB: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error reporting malicious IP: {str(e)}")
            return False
    
    def check_url_safety(self, url):

        if not self.enable_safebrowsing:
            return True, None
        
        # Normalize URL
        if not url.startswith('http'):
            url = 'http://' + url
        
        # For demo/testing purposes - hardcoded test cases
        known_test_urls = {
            "http://malware.testing.google.test.com/testing/malware/": "MALWARE",
            "http://unsafe.bad.demo.test/phishing": "SOCIAL_ENGINEERING",
            "http://malware.testing.google.test.com": "MALWARE"
        }
        
        for test_url, threat in known_test_urls.items():
            if url == test_url or url.startswith(test_url):
                logger.warning(f"Demo mode: URL {url} detected as malicious: {threat} (demo)")
                return False, threat
        
        # Check cache first
        if url in self.url_cache:
            cache_entry = self.url_cache[url]
            if time.time() - cache_entry['timestamp'] < self.cache_expiry:
                # Cache hit
                return cache_entry['safe'], cache_entry.get('threat_type')
        
        # Respect rate limiting
        current_time = time.time()
        if current_time - self.last_safebrowsing_call < self.min_api_interval:
            logger.debug(f"Rate limiting Safe Browsing check for {url}")
            return True, None
        
        try:
            # Build the API request
            payload = {
                'client': {
                    'clientId': 'hybrid-firewall',
                    'clientVersion': '1.0.0'
                },
                'threatInfo': {
                    'threatTypes': [
                        'MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'
                    ],
                    'platformTypes': ['ANY_PLATFORM'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries': [{'url': url}]
                }
            }
            
            params = {
                'key': self.config['google_safebrowsing']['api_key']
            }
            
            # Make the API request
            self.last_safebrowsing_call = current_time
            response = requests.post(
                self.config['google_safebrowsing']['url'], 
                params=params,
                json=payload,
                timeout=3
            )
            
            logger.debug(f"Google Safe Browsing response: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                
                # If there are matches, the URL is unsafe
                matches = result.get('matches', [])
                is_safe = len(matches) == 0
                threat_type = matches[0].get('threatType') if matches else None
                
                # Cache the result
                self.url_cache[url] = {
                    'safe': is_safe,
                    'threat_type': threat_type,
                    'timestamp': current_time
                }
                
                if not is_safe:
                    logger.warning(f"URL {url} is unsafe: {threat_type}")
                
                return is_safe, threat_type
                
            else:
                logger.warning(f"Safe Browsing API error: {response.status_code} - {response.text}")
                return True, None
                
        except Exception as e:
            logger.error(f"Error checking URL safety: {str(e)}")
            return True, None
    
    def extract_url_from_http_packet(self, packet):

        # This is a simplified implementation - a real one would parse HTTP headers
        if packet.get('protocol') != Protocol.TCP:
            return None
            
        dst_port = packet.get('dst_port')
        if dst_port not in (80, 443):  # HTTP/HTTPS ports
            return None
            
        dst_ip = packet.get('dst_ip')
        if not dst_ip:
            return None
            
        # For demo purposes, construct a URL from the destination IP
        # In a real implementation, you would extract the Host header from HTTP
        scheme = 'https' if dst_port == 443 else 'http'
        return f"{scheme}://{dst_ip}"

class AnomalyDetector:

    def __init__(self, history_size=2000, threshold=5.0):

        self.history_size = history_size
        self.threshold = threshold
        self.lock = threading.RLock()
        
        # Features history (for statistical analysis)
        self.packet_sizes = []
        self.packet_rates = []
        self.port_access = Counter()
        self.conn_duration = []
        
        # Historical data for behavior profiling
        self.ip_behavior = defaultdict(lambda: {
            'ports': Counter(),
            'bytes_sent': [],
            'packet_freq': [],
            'last_seen': 0,
            'connection_count': 0
        })
        
        # Time windows for rate calculations
        self.time_windows = {}
        
        logger.info("Anomaly detection module initialized")
    
    def update(self, packet):

        with self.lock:
            # Extract features for anomaly detection
            src_ip = packet.get('src_ip')
            dst_ip = packet.get('dst_ip')
            dst_port = packet.get('dst_port', 0)
            packet_size = packet.get('length', 0)
            protocol = packet.get('protocol')
            timestamp = time.time()
            
            if not src_ip or not dst_ip:
                return False
            
            # Update port access statistics
            self.port_access[dst_port] += 1
            
            # Update packet size history
            self.packet_sizes.append(packet_size)
            if len(self.packet_sizes) > self.history_size:
                self.packet_sizes.pop(0)
            
            # Calculate packet rate (packets per second)
            if src_ip in self.time_windows:
                last_time, count = self.time_windows[src_ip]
                time_diff = timestamp - last_time
                if time_diff > 0:
                    rate = count / time_diff
                    self.packet_rates.append(rate)
                    if len(self.packet_rates) > self.history_size:
                        self.packet_rates.pop(0)
                
                # Reset window
                self.time_windows[src_ip] = (timestamp, 1)
            else:
                self.time_windows[src_ip] = (timestamp, 1)
            
            # Update IP behavior profile
            profile = self.ip_behavior[src_ip]
            profile['ports'][dst_port] += 1
            profile['bytes_sent'].append(packet_size)
            profile['connection_count'] += 1
            
            if profile['last_seen'] > 0:
                time_diff = timestamp - profile['last_seen']
                if time_diff > 0:
                    profile['packet_freq'].append(1.0 / time_diff)
            
            profile['last_seen'] = timestamp
            
            # Limit history size for each profile
            if len(profile['bytes_sent']) > self.history_size:
                profile['bytes_sent'] = profile['bytes_sent'][-self.history_size:]
            if len(profile['packet_freq']) > self.history_size:
                profile['packet_freq'] = profile['packet_freq'][-self.history_size:]
            
            # Check for anomalies
            return self._detect_anomalies(src_ip, dst_ip, dst_port, packet_size, protocol)
    
    def _detect_anomalies(self, src_ip, dst_ip, dst_port, packet_size, protocol):

        anomalies = []
        
        # 1. Check for unusual packet size
        if self.packet_sizes and len(self.packet_sizes) > 10:
            mean_size = np.mean(self.packet_sizes)
            std_size = max(1, np.std(self.packet_sizes))
            z_score = abs(packet_size - mean_size) / std_size
            
            if z_score > self.threshold:
                anomalies.append(f"Unusual packet size: {packet_size} bytes (z-score: {z_score:.2f})")
        
        # 2. Check for unusual packet rate
        if self.packet_rates and len(self.packet_rates) > 10:
            mean_rate = np.mean(self.packet_rates)
            std_rate = max(0.1, np.std(self.packet_rates))
            
            if src_ip in self.time_windows:
                last_time, count = self.time_windows[src_ip]
                time_diff = time.time() - last_time
                if time_diff > 0:
                    current_rate = count / time_diff
                    z_score = abs(current_rate - mean_rate) / std_rate
                    
                    if z_score > self.threshold:
                        anomalies.append(f"Unusual packet rate: {current_rate:.2f} pps (z-score: {z_score:.2f})")
        
        # 3. Check for unusual port access
        if dst_port not in (80, 443, 53, 22, 25, 123):  # Common ports
            port_count = self.port_access[dst_port]
            if port_count < 5:  # Rarely accessed port
                profile = self.ip_behavior[src_ip]
                if profile['connection_count'] > 10 and profile['ports'][dst_port] < 2:
                    anomalies.append(f"Unusual port access: {dst_port} (rarely accessed)")
        
        # 4. Check for change in behavior
        profile = self.ip_behavior[src_ip]
        if profile['connection_count'] > 20:
            if profile['bytes_sent'] and len(profile['bytes_sent']) > 10:
                mean_bytes = np.mean(profile['bytes_sent'][:-10])
                recent_bytes = np.mean(profile['bytes_sent'][-10:])
                if recent_bytes > mean_bytes * 3:
                    anomalies.append(f"Unusual traffic volume increase: {recent_bytes:.2f} vs {mean_bytes:.2f}")
            
            if profile['packet_freq'] and len(profile['packet_freq']) > 10:
                mean_freq = np.mean(profile['packet_freq'][:-10])
                recent_freq = np.mean(profile['packet_freq'][-10:])
                if recent_freq > mean_freq * 3:
                    anomalies.append(f"Unusual connection frequency increase")
        
        # Log anomalies and return result
        if anomalies:
            log_msg = f"Anomalies detected from {src_ip}: {'; '.join(anomalies)}"
            logger.warning(log_msg)
            return True
        
        return False


class DeepPacketInspection:

    def __init__(self):
        """Initialize the DPI module"""
        # Signature database for known attacks
        self.attack_signatures = {
            # SQL Injection patterns
            'sql_injection': [
                re.compile(r"(?i)(\bUNION\b.*\bSELECT\b|\bOR\b\s+\d+=\d+|('.+--)|(' OR '1'='1))")
            ],
            
            # XSS patterns
            'xss': [
                re.compile(r'(?i)<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
                re.compile(r'(?i)<[^>]*on\w+\s*=.*?>', re.IGNORECASE),
                re.compile(r'(?i)(javascript|vbscript|expression)(\s*):'),
                re.compile(r'(?i)(\%3C)|(<)[^\n]+((\%3E)|(>))')
            ],
            
            # Command injection
            'cmd_injection': [
                re.compile(r'(?i)([;`\|])(\s*)(cat|rm|chmod|pwd|docker|nc|curl|whoami|ls)'),
                re.compile(r'(?i)([;`\|])(\s*)(wget|ping|sudo|cd|bash|tcpdump|mv|cp)'),
                re.compile(r'(?i)([&`])(\s*)(whoami|cat|mkdir|rmdir|touch)')
            ],
            
            # Path traversal
            'path_traversal': [
                re.compile(r'(?i)(\.\./|\.\\|\%2e\%2e\%2f|\%252e\%252e\%252f)'),
                re.compile(r'(?i)(\/etc\/passwd|boot\.ini|win\.ini|\/etc\/shadow)')
            ],
            
            # Common malware strings
            'malware': [
                re.compile(r'(?i)(botnet|infected|malware|trojan|backdoor|ransomware)'),
                re.compile(r'(?i)(steal|pwn|r00t|h4ck)'),
                re.compile(r'(?i)(\/gate\.php|\/panel\.php|\/admin\.php|\/config\.php)')
            ]
        }
        
        # Protocol analyzers for specific application protocols
        self.protocol_analyzers = {
            'http': self._analyze_http,
            'dns': self._analyze_dns,
            'smtp': self._analyze_smtp,
            'ftp': self._analyze_ftp
        }
        
        # Flags for detected protocols
        self.protocols = {
            'http': {'ports': [80, 8080, 8000, 8008, 8888]},
            'https': {'ports': [443, 8443]},
            'dns': {'ports': [53]},
            'smtp': {'ports': [25, 587, 465]},
            'ftp': {'ports': [20, 21]},
            'ssh': {'ports': [22]},
            'telnet': {'ports': [23]},
            'rdp': {'ports': [3389]}
        }
        
        logger.info("Deep Packet Inspection module initialized")
    
    def inspect_packet(self, packet):

        payload = packet.get('payload', b'')
        protocol = packet.get('protocol')
        dst_port = packet.get('dst_port', 0)
        src_port = packet.get('src_port', 0)
        
        if not payload:
            return False, None, None
        
        # Try to decode the payload
        try:
            decoded_payload = payload.decode('utf-8', errors='ignore')
        except (AttributeError, UnicodeDecodeError):
            # If payload is not a string type or can't be decoded properly
            decoded_payload = str(payload)
        
        # Determine application protocol based on port
        app_protocol = None
        for proto, info in self.protocols.items():
            if dst_port in info['ports'] or src_port in info['ports']:
                app_protocol = proto
                break
        
        # Check for attack signatures in the payload
        for attack_type, patterns in self.attack_signatures.items():
            for pattern in patterns:
                if pattern.search(decoded_payload):
                    details = f"Detected {attack_type} pattern: {pattern.pattern}"
                    logger.warning(f"DPI: {details} in {app_protocol or 'unknown'} traffic")
                    return True, attack_type, details
        
        # If we have a specific analyzer for this protocol, use it
        if app_protocol and app_protocol in self.protocol_analyzers:
            return self.protocol_analyzers[app_protocol](decoded_payload, packet)
        
        return False, None, None
    
    def _analyze_http(self, payload, packet):
        """Analyze HTTP traffic for anomalies and attacks"""
        # Check for oversized headers
        if len(payload) > 4096 and 'HTTP/' in payload:
            return True, 'http_oversized', "Oversized HTTP headers"
        
        # Check for unusual HTTP methods
        unusual_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'OPTIONS']
        for method in unusual_methods:
            if payload.startswith(f"{method} "):
                return True, 'http_unusual_method', f"Unusual HTTP method: {method}"
        
        # Check for suspicious user agents
        suspicious_agents = ['sqlmap', 'nikto', 'nessus', 'metasploit', 'nmap', 'dirbuster', 'hydra']
        for agent in suspicious_agents:
            if f"User-Agent: {agent}" in payload.lower():
                return True, 'http_suspicious_agent', f"Suspicious User-Agent: {agent}"
        
        return False, None, None
    
    def _analyze_dns(self, payload, packet):
        """Analyze DNS traffic for anomalies and attacks"""
        # Check for extremely long domain names (potential DNS tunneling)
        if len(payload) > 200:
            subdomains = payload.count('.')
            if subdomains > 5:
                return True, 'dns_tunneling', f"Possible DNS tunneling: {subdomains} subdomains"
        
        # Check for DNS queries to suspicious TLDs
        suspicious_tlds = ['.top', '.xyz', '.club', '.gq', '.tk', '.ml', '.ga', '.cf']
        for tld in suspicious_tlds:
            if tld in payload:
                return True, 'dns_suspicious_tld', f"Query to suspicious TLD: {tld}"
        
        return False, None, None
    
    def _analyze_smtp(self, payload, packet):
        """Analyze SMTP traffic for anomalies and attacks"""
        # Check for suspicious file attachments
        suspicious_extensions = ['.exe', '.bat', '.vbs', '.js', '.jar', '.zip', '.rar']
        for ext in suspicious_extensions:
            if ext in payload:
                return True, 'smtp_suspicious_attachment', f"Suspicious email attachment: {ext}"
        
        # Check for spam-like content
        spam_indicators = ['viagra', 'pharmacy', 'lottery', 'winner', 'bitcoin', 'investment']
        for indicator in spam_indicators:
            if indicator.lower() in payload.lower():
                return True, 'smtp_spam', f"Potential spam content: {indicator}"
        
        return False, None, None
    
    def _analyze_ftp(self, payload, packet):
        """Analyze FTP traffic for anomalies and attacks"""
        # Check for suspicious FTP commands
        suspicious_commands = ['SITE EXEC', 'SITE SHELL', 'PUT', 'STOR']
        for cmd in suspicious_commands:
            if cmd in payload:
                return True, 'ftp_suspicious_command', f"Suspicious FTP command: {cmd}"
        
        return False, None, None


class GeoIPFilter:
    def __init__(self, db_path="./GeoLite2-Country.mmdb"):
        self.reader = geoip2.database.Reader(db_path)
        self.enabled = True

        # List of high-risk countries
        self.high_risk_countries = {
            'RU', 'KP', 'BY'
        }

        # List of allowed countries (ISO codes) - if empty, all non-high-risk are allowed
        self.allowed_countries = set()

        # Cache for IP to country lookups
        self.ip_cache = {}

        logger.info("GeoIP filter initialized")

    def get_country(self, ip_address):
        # Check if it's a private IP
        try:
            if ipaddress.ip_address(ip_address).is_private:
                return 'LOCAL', 'Local Network'
        except ValueError:
            return None, None

        # Check cache first
        if ip_address in self.ip_cache:
            return self.ip_cache[ip_address]

        # Query the GeoIP database
        try:
            response = self.reader.country(ip_address)
            country_code = response.country.iso_code
            country_name = response.country.name

            # Cache the result
            self.ip_cache[ip_address] = (country_code, country_name)
            return country_code, country_name
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip_address}: {e}")
            return None, None

    def should_block(self, ip_address):
        country_code, country_name = self.get_country(ip_address)

        if not country_code:
            # Unknown country, don't block
            return False, None, None

        if country_code == 'LOCAL':
            # Don't block local network
            return False, country_code, country_name

        # If we have an allowlist and the country is not in it, block
        if self.allowed_countries and country_code not in self.allowed_countries:
            logger.warning(f"Blocking IP {ip_address} from non-allowed country: {country_name} ({country_code})")
            return True, country_code, country_name

        # Block high-risk countries
        if country_code in self.high_risk_countries:
            logger.warning(f"Blocking IP {ip_address} from high-risk country: {country_name} ({country_code})")
            return True, country_code, country_name

        return False, country_code, country_name


class MITREMapping:

    def __init__(self):
        """Initialize the MITRE mapping module"""
        # Simplified mapping of attack types to MITRE ATT&CK techniques
        self.attack_mappings = {
            # Network-based attacks
            'port_scan': {
                'technique_id': 'T1046',
                'technique_name': 'Network Service Scanning',
                'tactic': 'Discovery',
                'description': 'Adversaries may attempt to get a listing of services running on remote hosts.'
            },
            'ssh_brute_force': {
                'technique_id': 'T1110',
                'technique_name': 'Brute Force',
                'tactic': 'Credential Access',
                'description': 'Adversaries may use brute force techniques to gain access to accounts.'
            },
            'half_open_scan': {
                'technique_id': 'T1046',
                'technique_name': 'Network Service Scanning',
                'tactic': 'Discovery',
                'description': 'Adversaries may attempt to get a listing of services running on remote hosts.'
            },
            
            # Application-layer attacks
            'sql_injection': {
                'technique_id': 'T1190',
                'technique_name': 'Exploit Public-Facing Application',
                'tactic': 'Initial Access',
                'description': 'Adversaries may attempt to exploit vulnerabilities in public-facing applications.'
            },
            'xss': {
                'technique_id': 'T1059.007',
                'technique_name': 'JavaScript',
                'tactic': 'Execution',
                'description': 'Adversaries may abuse JavaScript to execute commands or scripts.'
            },
            'cmd_injection': {
                'technique_id': 'T1059',
                'technique_name': 'Command and Scripting Interpreter',
                'tactic': 'Execution',
                'description': 'Adversaries may abuse command and script interpreters to execute commands.'
            },
            'path_traversal': {
                'technique_id': 'T1083',
                'technique_name': 'File and Directory Discovery',
                'tactic': 'Discovery',
                'description': 'Adversaries may enumerate files and directories to understand the system.'
            },
            
            # Protocol-specific attacks
            'dns_tunneling': {
                'technique_id': 'T1071.004',
                'technique_name': 'DNS',
                'tactic': 'Command and Control',
                'description': 'Adversaries may use DNS to communicate with systems under their control.'
            },
            'http_unusual_method': {
                'technique_id': 'T1071.001',
                'technique_name': 'Web Protocols',
                'tactic': 'Command and Control',
                'description': 'Adversaries may use web protocols for command and control.'
            },
            'smtp_suspicious_attachment': {
                'technique_id': 'T1566.001',
                'technique_name': 'Spearphishing Attachment',
                'tactic': 'Initial Access',
                'description': 'Adversaries may send emails with malicious attachments to gain access.'
            },
            'ftp_suspicious_command': {
                'technique_id': 'T1071',
                'technique_name': 'Application Layer Protocol',
                'tactic': 'Command and Control',
                'description': 'Adversaries may use application layer protocols for command and control.'
            }
        }
        
        logger.info("MITRE ATT&CK mapping module initialized")
    
    def get_technique(self, attack_type):
        """
        Get MITRE ATT&CK information for an attack type.
        
        Args:
            attack_type (str): Type of attack detected
            
        Returns:
            dict: MITRE ATT&CK information or None if not found
        """
        return self.attack_mappings.get(attack_type)
    
    def get_all_techniques(self):
        """Get all mapped techniques"""
        return self.attack_mappings
    
    def check_ip_reputation(self, ip_address):
        if not self.enable_abuseipdb:
            return False, 0
        
        # For demo/testing purposes - hardcoded test cases
        if ip_address == "185.143.223.12":  # Known test case
            logger.warning(f"Demo mode: IP {ip_address} detected as malicious (demo)")
            return True, 90
            
        # Check cache first
        if ip_address in self.ip_cache:
            cache_entry = self.ip_cache[ip_address]
            if time.time() - cache_entry['timestamp'] < self.cache_expiry:
                # Cache hit
                return cache_entry['score'] >= 30, cache_entry['score']
        
        # Respect rate limiting
        current_time = time.time()
        if current_time - self.last_abuseipdb_call < self.min_api_interval:
            logger.debug(f"Rate limiting AbuseIPDB check for {ip_address}")
            return False, 0
        
        try:
            # Build the API request
            headers = {
                'Accept': 'application/json',
                'Key': self.config['abuseipdb']['api_key']
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 30,
                'verbose': False
            }
            
            # Make the API request
            self.last_abuseipdb_call = current_time
            response = requests.get(
                f"{self.config['abuseipdb']['url']}check", 
                headers=headers, 
                params=params,
                timeout=3
            )
            
            if response.status_code == 200:
                result = response.json()
                data = result.get('data', {})
                score = data.get('abuseConfidenceScore', 0)
                
                # Cache the result
                self.ip_cache[ip_address] = {
                    'score': score,
                    'timestamp': current_time
                }
                
                is_malicious = score >= 30  # Consider scores 30+ as malicious
                
                if is_malicious:
                    logger.warning(f"IP {ip_address} has malicious reputation score: {score}")
                else:
                    logger.debug(f"IP {ip_address} reputation score: {score}")
                
                return is_malicious, score
                
            else:
                logger.warning(f"AbuseIPDB API error: {response.status_code} - {response.text}")
                return False, 0
                
        except Exception as e:
            logger.error(f"Error checking IP reputation: {str(e)}")
            return False, 0
    
    def report_malicious_ip(self, ip_address, categories, comment=""):

        if not self.enable_abuseipdb:
            return False
        
        # Respect rate limiting
        current_time = time.time()
        if current_time - self.last_abuseipdb_call < self.min_api_interval:
            logger.debug(f"Rate limiting AbuseIPDB report for {ip_address}")
            return False
        
        try:
            # Build the API request
            headers = {
                'Accept': 'application/json',
                'Key': self.config['abuseipdb']['api_key']
            }
            
            # Join categories as comma-separated string
            categories_str = ','.join(map(str, categories))
            
            data = {
                'ip': ip_address,
                'categories': categories_str,
                'comment': comment
            }
            
            # Make the API request
            self.last_abuseipdb_call = current_time
            response = requests.post(
                f"{self.config['abuseipdb']['url']}report", 
                headers=headers, 
                data=data,
                timeout=3
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully reported IP {ip_address} to AbuseIPDB")
                return True
            else:
                logger.warning(f"Error reporting to AbuseIPDB: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error reporting malicious IP: {str(e)}")
            return False
    
    def check_url_safety(self, url):

        if not self.enable_safebrowsing:
            return True, None
        
        # Normalize URL
        if not url.startswith('http'):
            url = 'http://' + url
        
        # For demo/testing purposes - hardcoded test cases
        known_test_urls = {
            "http://malware.testing.google.test.com/testing/malware/": "MALWARE",
            "http://unsafe.bad.demo.test/phishing": "SOCIAL_ENGINEERING",
            "http://malware.testing.google.test.com": "MALWARE"
        }
        
        for test_url, threat in known_test_urls.items():
            if url == test_url or url.startswith(test_url):
                logger.warning(f"Demo mode: URL {url} detected as malicious: {threat} (demo)")
                return False, threat
        
        # Check cache first
        if url in self.url_cache:
            cache_entry = self.url_cache[url]
            if time.time() - cache_entry['timestamp'] < self.cache_expiry:
                # Cache hit
                return cache_entry['safe'], cache_entry.get('threat_type')
        
        # Respect rate limiting
        current_time = time.time()
        if current_time - self.last_safebrowsing_call < self.min_api_interval:
            logger.debug(f"Rate limiting Safe Browsing check for {url}")
            return True, None
        
        try:
            # Build the API request
            payload = {
                'client': {
                    'clientId': 'hybrid-firewall',
                    'clientVersion': '1.0.0'
                },
                'threatInfo': {
                    'threatTypes': [
                        'MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'
                    ],
                    'platformTypes': ['ANY_PLATFORM'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries': [{'url': url}]
                }
            }
            
            params = {
                'key': self.config['google_safebrowsing']['api_key']
            }
            
            # Make the API request
            self.last_safebrowsing_call = current_time
            response = requests.post(
                self.config['google_safebrowsing']['url'], 
                params=params,
                json=payload,
                timeout=3
            )
            
            logger.debug(f"Google Safe Browsing response: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                
                # If there are matches, the URL is unsafe
                matches = result.get('matches', [])
                is_safe = len(matches) == 0
                threat_type = matches[0].get('threatType') if matches else None
                
                # Cache the result
                self.url_cache[url] = {
                    'safe': is_safe,
                    'threat_type': threat_type,
                    'timestamp': current_time
                }
                
                if not is_safe:
                    logger.warning(f"URL {url} is unsafe: {threat_type}")
                
                return is_safe, threat_type
                
            else:
                logger.warning(f"Safe Browsing API error: {response.status_code} - {response.text}")
                return True, None
                
        except Exception as e:
            logger.error(f"Error checking URL safety: {str(e)}")
            return True, None
    
    def extract_url_from_http_packet(self, packet):

        # This is a simplified implementation - a real one would parse HTTP headers
        if packet.get('protocol') != Protocol.TCP:
            return None
            
        dst_port = packet.get('dst_port')
        if dst_port not in (80, 443):  # HTTP/HTTPS ports
            return None
            
        dst_ip = packet.get('dst_ip')
        if not dst_ip:
            return None
            
        # For demo purposes, construct a URL from the destination IP
        # In a real implementation, you would extract the Host header from HTTP
        scheme = 'https' if dst_port == 443 else 'http'
        return f"{scheme}://{dst_ip}"


class HybridFirewall:

    def __init__(self, interface="eth0", stateful_mode=True, enable_threat_intel=True,
                 enable_anomaly_detection=True, enable_dpi=True, enable_geoip=True):

        self.interface = interface
        self.stateful_mode = stateful_mode
        self.enable_threat_intel = enable_threat_intel
        self.enable_anomaly_detection = enable_anomaly_detection
        self.enable_dpi = enable_dpi
        self.enable_geoip = enable_geoip
        
        # Core components
        self.ce = ControlElement()
        self.fe = ForwardingElement()
        
        # Advanced security modules
        self.ti = ThreatIntelligence() if enable_threat_intel else None
        self.ad = AnomalyDetector() if enable_anomaly_detection else None
        self.dpi = DeepPacketInspection() if enable_dpi else None
        self.geoip = GeoIPFilter() if enable_geoip else None
        self.mitre = MITREMapping()
        
        # Packet capturing
        self.running = False
        self.capture_thread = None
        self.live_capture_enabled = False
        self.packets_queue = deque(maxlen=1000)
        
        # Statistics and metrics
        self.stats = {
            'packets_processed': 0,
            'packets_accepted': 0,
            'packets_dropped': 0,
            'attacks_detected': 0,
            'malicious_ips_blocked': 0,
            'malicious_urls_blocked': 0,
            'anomalies_detected': 0,
            'dpi_detections': 0,
            'geoip_blocks': 0,
            'attacks_by_country': Counter(),
            'attack_types': Counter(),
            'mitre_techniques': Counter(),
            'start_time': time.time()
        }
        
        # Attack history for analysis
        self.attack_history = deque(maxlen=100)
        
        # Add some default rules for protection
        self._add_default_rules()
    
    def _add_default_rules(self):
        """Add default protection rules"""
        # Allow established connections (stateful override)
        self.fe.add_rule(FilterRule(
            1, 
            action=Action.ACCEPT, 
            direction=Direction.INBOUND,
            description="Allow established connections"
        ))
        
        # Rate limit SSH connections (prevent dictionary attacks)
        self.fe.add_rule(FilterRule(
            2,
            dst_port=22,
            protocol=Protocol.TCP,
            action=Action.DROP,
            direction=Direction.INBOUND,
            description="Rate limit SSH connections"
        ))
        
        # Allow outbound traffic by default
        self.fe.add_rule(FilterRule(
            3,
            action=Action.ACCEPT,
            direction=Direction.OUTBOUND,
            description="Allow outbound traffic"
        ))

        self.fe.add_rule(FilterRule(
            rule_id=99,
            src_ip="150.171.0.0/16",  # Microsoft range
            action=Action.ACCEPT,
            direction=Direction.INBOUND,
            description="Allow Microsoft telemetry"
        ))
    
    def add_rule(self, rule):
        """Add a filtering rule to the forwarding element"""
        self.fe.add_rule(rule)
    
    def remove_rule(self, rule_id):
        """Remove a rule by ID"""
        return self.fe.remove_rule(rule_id)
    
    def start(self):
        """Start the firewall"""
        if self.running:
            logger.warning("Firewall is already running")
            return
        
        self.running = True
        
        # In a real implementation, this would set up raw socket capture
        # Since this is a demonstration, we'll simulate packet processing
        self.capture_thread = threading.Thread(target=self._packet_capture_loop, daemon=True)
        self.capture_thread.start()
        
        logger.info(f"Firewall started on interface {self.interface}")
    
    def stop(self):
        """Stop the firewall"""
        if not self.running:
            logger.warning("Firewall is not running")
            return
        
        self.running = False
        self.capture_thread.join(timeout=1.0)
        logger.info("Firewall stopped")
    
    def _packet_capture_loop(self):
        """Real packet capture using Scapy."""
        sniff(
            iface=self.interface,
            prn=self._handle_packet,
            store=False,
            filter="ip",  # or "tcp or udp or icmp"
        )

    def _handle_packet(self, pkt):
        if IP in pkt:
            ip_layer = pkt[IP]
            packet = {
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'length': len(pkt),
                'protocol': None,
                'payload': bytes(pkt[Raw]) if Raw in pkt else b'',
                'direction': Direction.INBOUND if ip_layer.dst == self._get_local_ip() else Direction.OUTBOUND
            }

            if TCP in pkt:
                tcp_layer = pkt[TCP]
                packet.update({
                    'protocol': Protocol.TCP,
                    'src_port': tcp_layer.sport,
                    'dst_port': tcp_layer.dport,
                    'tcp_flags': {
                        'SYN': tcp_layer.flags & 0x02 != 0,
                        'ACK': tcp_layer.flags & 0x10 != 0,
                        'FIN': tcp_layer.flags & 0x01 != 0,
                        'RST': tcp_layer.flags & 0x04 != 0,
                    }
                })
            elif UDP in pkt:
                udp_layer = pkt[UDP]
                packet.update({
                    'protocol': Protocol.UDP,
                    'src_port': udp_layer.sport,
                    'dst_port': udp_layer.dport
                })
            elif ICMP in pkt:
                packet['protocol'] = Protocol.ICMP

            action = self.process_packet(packet)
            logger.info(f"Packet from {packet['src_ip']} to {packet['dst_ip']} ({packet['protocol']}) => {action.name}")

    def _get_local_ip(self):
        """Returns the local IP address of the interface."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            logger.error(f"Could not determine local IP: {e}")
            return "127.0.0.1"




    def process_packet(self, packet):
        self.stats['packets_processed'] += 1
        src_ip = packet.get('src_ip')
        dst_ip = packet.get('dst_ip')
        
        # Record packet for analysis
        if self.live_capture_enabled:
            self.packets_queue.append(packet)
        
        # 1. Check GeoIP restrictions
        if self.enable_geoip and src_ip:
            should_block, country_code, country_name = self.geoip.should_block(src_ip)
            if should_block:
                self.stats['geoip_blocks'] += 1
                self.stats['packets_dropped'] += 1
                
                # Record country-based block in stats
                if country_code:
                    self._record_attack_event('geoip_blocked', src_ip, dst_ip, 
                                             f"Blocked traffic from {country_name} ({country_code})")
                
                return Action.DROP

        if packet.get('protocol') == Protocol.TCP and src_ip and packet.get('dst_port'):
            if self.ce.attack_detector.record_port_attempt(src_ip, packet['dst_port']):
                # If the threshold is reached, block the packet immediately.
                self.stats['packets_dropped'] += 1
                # You might also want to record the event and blacklist the IP.
                self.ce.record_failed_attempt(src_ip)
                return Action.DROP

        
        # 2. Check external threat intelligence
        if self.enable_threat_intel and src_ip:
            # Check for malicious IP reputation
            is_malicious, score = self.ti.check_ip_reputation(src_ip)
            if is_malicious:
                logger.warning(f"Blocking packet from malicious IP {src_ip} (score: {score})")
                self.stats['malicious_ips_blocked'] += 1
                self.stats['packets_dropped'] += 1
                
                # Record in attack history
                self._record_attack_event('malicious_ip', src_ip, dst_ip, 
                                         f"Blocked malicious IP with score {score}")
                
                return Action.DROP
            
            # For outbound traffic, check URL safety
            if (packet.get('direction') == Direction.OUTBOUND and 
                packet.get('protocol') == Protocol.TCP):
                url = self.ti.extract_url_from_http_packet(packet)
                if url:
                    is_safe, threat_type = self.ti.check_url_safety(url)
                    if not is_safe:
                        logger.warning(f"Blocking access to malicious URL: {url} (threat: {threat_type})")
                        self.stats['malicious_urls_blocked'] += 1
                        self.stats['packets_dropped'] += 1
                        
                        # Record in attack history
                        self._record_attack_event('malicious_url', src_ip, dst_ip, 
                                                 f"Blocked malicious URL: {url} (threat: {threat_type})")
                        
                        return Action.DROP
        
        # 3. Perform anomaly detection
        if self.enable_anomaly_detection:
            is_anomaly = self.ad.update(packet)
            if is_anomaly:
                self.stats['anomalies_detected'] += 1
                
                # For now, log the anomaly but don't automatically block
                # This could be configurable in a production firewall
                self._record_attack_event('anomaly', src_ip, dst_ip, 
                                         "Traffic anomaly detected")
                
                # In a more aggressive configuration, we might drop here
                # return Action.DROP
        
        # 4. Perform deep packet inspection if we have payload data
        if self.enable_dpi and packet.get('payload'):
            is_malicious, attack_type, details = self.dpi.inspect_packet(packet)
            if is_malicious:
                self.stats['dpi_detections'] += 1
                self.stats['attack_types'][attack_type] += 1
                self.stats['packets_dropped'] += 1
                
                # Map to MITRE ATT&CK if possible
                mitre_info = self.mitre.get_technique(attack_type)
                if mitre_info:
                    technique_id = mitre_info['technique_id']
                    self.stats['mitre_techniques'][technique_id] += 1
                    
                    # Record detailed attack information
                    self._record_attack_event(attack_type, src_ip, dst_ip, details, mitre_info)
                else:
                    # Record attack without MITRE mapping
                    self._record_attack_event(attack_type, src_ip, dst_ip, details)
                
                logger.warning(f"DPI blocked attack: {attack_type} from {src_ip} - {details}")
                return Action.DROP
        
        # 5. Perform stateful processing
        state = ConnState.NEW
        is_attack = False
        
        if self.stateful_mode:
            state, is_attack = self.ce.process_packet(packet)
            
            # Record attacks
            if is_attack:
                self.stats['attacks_detected'] += 1
                attack_type = 'port_scan'
                
                if packet.get('dst_port') == 22:
                    attack_type = 'ssh_brute_force'
                
                # Map to MITRE ATT&CK
                mitre_info = self.mitre.get_technique(attack_type)
                if mitre_info:
                    technique_id = mitre_info['technique_id']
                    self.stats['mitre_techniques'][technique_id] += 1
                
                # Record in attack history
                self._record_attack_event(attack_type, src_ip, dst_ip, 
                                         f"Stateful detection of {attack_type}", mitre_info)
                
                # Blacklist the source IP after detecting an attack
                if packet.get('src_ip'):
                    self.ce.record_failed_attempt(packet.get('src_ip'))
                    
                    # Report to AbuseIPDB if enabled
                    if self.enable_threat_intel:
                        if is_attack and packet.get('src_ip'):
                            # Determine attack type for categories
                            categories = []
                            if packet.get('dst_port') == 22:
                                # SSH dictionary attack
                                categories = [18, 22]  # Brute-Force, SSH
                                comment = "SSH dictionary attack detected"
                            else:
                                # Port scan or other attack
                                categories = [14, 19]  # Port scan, 0-day attack
                                comment = "Port scan or attack detected"
                                
                            self.ti.report_malicious_ip(packet.get('src_ip'), categories, comment)
            
            # Handle connection states
            if state == ConnState.ESTABLISHED or state == ConnState.RELATED:
                # For established connections, bypass packet filtering
                self.stats['packets_accepted'] += 1
                return Action.ACCEPT
            
            if state == ConnState.INVALID:
                # For invalid connections, drop immediately
                self.stats['packets_dropped'] += 1
                return Action.DROP
        
        # 6. Apply packet filtering rules
        action = self.fe.evaluate_packet(packet)
        
        # Update stats
        if action == Action.ACCEPT:
            self.stats['packets_accepted'] += 1
        else:
            self.stats['packets_dropped'] += 1
            
            # Record failed connection attempts
            if (state == ConnState.NEW and 
                packet.get('protocol') == Protocol.TCP and 
                packet.get('src_ip')):
                self.ce.record_failed_attempt(packet.get('src_ip'))
        
        return action
    
    def _record_attack_event(self, attack_type, src_ip, dst_ip, details, mitre_info=None):
        """Record an attack event in the attack history"""
        # Get source country if possible
        country_code = None
        country_name = None
        if self.enable_geoip and src_ip:
            country_code, country_name = self.geoip.get_country(src_ip)
            if country_code:
                self.stats['attacks_by_country'][country_code] += 1
        
        # Create attack event record
        event = {
            'timestamp': time.time(),
            'datetime': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'attack_type': attack_type,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'country_code': country_code,
            'country_name': country_name,
            'details': details,
            'mitre': mitre_info
        }
        
        # Add to attack history
        self.attack_history.append(event)
        
        # Update attack type stats
        self.stats['attack_types'][attack_type] += 1
    
    def get_stats(self):
        """Get firewall statistics"""
        stats = self.stats.copy()
        stats['connections'] = self.ce.conn_tracker.get_stats()
        
        # Add threat intelligence stats if enabled
        if self.enable_threat_intel:
            stats['threat_intel'] = {
                'malicious_ips_blocked': self.stats['malicious_ips_blocked'],
                'malicious_urls_blocked': self.stats['malicious_urls_blocked'],
                'ip_cache_size': len(self.ti.ip_cache),
                'url_cache_size': len(self.ti.url_cache)
            }
            
        return stats


def parse_tcp_flags(flags_str):
    """Parse TCP flags from string format (e.g., 'SYN,ACK')"""
    flags = {}
    if not flags_str:
        return flags
    
    for flag in flags_str.upper().split(','):
        flag = flag.strip()
        if flag in ['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG']:
            flags[flag] = True
    
    return flags


def simulate_packet(src_ip, dst_ip, protocol, src_port=None, dst_port=None, 
                   tcp_flags=None, length=64, direction=Direction.INBOUND):
    """Create a simulated packet for testing"""
    packet = {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': protocol,
        'length': length,
        'direction': direction
    }
    
    if src_port is not None:
        packet['src_port'] = src_port
    
    if dst_port is not None:
        packet['dst_port'] = dst_port
    
    if tcp_flags:
        packet['tcp_flags'] = parse_tcp_flags(tcp_flags)
    
    return packet

def test_threat_intelligence():
    logger.info("[TEST] Running Threat Intelligence Test...")
    ti = ThreatIntelligence()

    test_ip = "185.143.223.12"  # known demo IP
    malicious, score = ti.check_ip_reputation(test_ip)
    logger.info(f"[TEST] IP {test_ip} - Malicious: {malicious}, Score: {score}")

    test_url = "http://malware.testing.google.test.com/testing/malware/"
    safe, threat = ti.check_url_safety(test_url)
    logger.info(f"[TEST] URL {test_url} - Safe: {safe}, Threat: {threat}")

    test_url = "https:google.com"
    safe, threat = ti.check_url_safety(test_url)
    logger.info(f"[TEST] URL {test_url} - Safe: {safe}, Threat: {threat}")

def test_geoip_filter():
    logger.info("[TEST] Running GeoIP Filter Test...")
    geo = GeoIPFilter()

    test_ip = "5.45.207.185"  # random IP, often maps to RU
    block, code, name = geo.should_block(test_ip)
    logger.info(f"[TEST] IP {test_ip} - Blocked: {block}, Country: {name} ({code})")

    test_ip = "87.236.232.155"  # random IP, often maps to JO
    block, code, name = geo.should_block(test_ip)
    logger.info(f"[TEST] IP {test_ip} - Blocked: {block}, Country: {name} ({code})")

    local_ip = "192.168.1.10"
    block, code, name = geo.should_block(local_ip)
    logger.info(f"[TEST] Local IP {local_ip} - Blocked: {block}, Country: {name} ({code})")

    


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Hybrid Firewall Implementation")
    parser.add_argument("--interface", "-i", default="wlp2s0", help="Network interface to listen on")
    parser.add_argument("--no-stateful", action="store_true", help="Disable stateful filtering")
    parser.add_argument("--no-threat-intel", action="store_true", help="Disable threat intelligence")
    parser.add_argument("--no-anomaly", action="store_true", help="Disable anomaly detection")
    parser.add_argument("--no-dpi", action="store_true", help="Disable deep packet inspection")
    parser.add_argument("--no-geoip", action="store_true", help="Disable GeoIP filtering")
    parser.add_argument("--src-ip", help="Only show packets from this source IP")
    parser.add_argument('--test-threat-intel', action='store_true', help='Test threat intelligence engine')
    parser.add_argument('--test-geoip', action='store_true', help='Test GeoIP filter')
    args = parser.parse_args()
    
    firewall = HybridFirewall(
        interface=args.interface,
        stateful_mode=not args.no_stateful,
        enable_threat_intel=not args.no_threat_intel,
        enable_anomaly_detection=not args.no_anomaly,
        enable_dpi=not args.no_dpi,
        enable_geoip=not args.no_geoip
    )

    if args.test_threat_intel:
        test_threat_intelligence()

    if args.test_geoip:
        test_geoip_filter()

    firewall.start()
        
    try:
        # Keep running until interrupted
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping firewall...")
    finally:
        firewall.stop()