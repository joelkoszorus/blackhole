import socket
import threading
import time
import yaml
import requests
import sys
import os
import traceback
from flask import Flask, render_template, request, jsonify
from collections import deque
from dns import message, query, rdatatype, rrset, exception

# Configuration (will be loaded from config.yaml later)
CONFIG = {
    'UPSTREAM_DNS': '8.8.8.8',
    'SINKHOLE_IP': '0.0.0.0',
    'BLOCKLIST_URL': '', # Placeholder
    'BLOCKLIST_REFRESH_INTERVAL': 3600, # seconds
    'WEB_DASHBOARD_PORT': 8080,
    'DNS_PORT': 53,
    'DNS_HOST': '0.0.0.0',
}

# In-memory blocklist (domains will be stored as sets for fast lookup)
BLOCKLIST = set()
ALLOWLIST = set() # Domains to always allow, overriding the blocklist
DENYLIST = set()  # Domains to always block, overriding allowlist and blocklist

# Global statistics and logs
total_queries = 0
blocked_queries = 0
dns_logs = deque(maxlen=100) # Store last 100 log entries
stats_lock = threading.Lock() # Lock for thread-safe updates to stats and logs
list_lock = threading.Lock() # Lock for thread-safe updates to ALLOWLIST and DENYLIST

# Flask app instance
app = Flask(__name__)

def load_config(config_path="config.yaml"):
    global CONFIG
    # Construct absolute path to config.yaml
    script_dir = os.path.dirname(os.path.abspath(__file__))
    absolute_config_path = os.path.join(script_dir, config_path)
    try:
        with open(absolute_config_path, 'r') as f:
            CONFIG.update(yaml.safe_load(f))
        print("Configuration loaded successfully from " + absolute_config_path)
    except FileNotFoundError:
        print(f"Configuration file {absolute_config_path} not found. Using default settings.")
    except Exception as e:
        print(f"Error loading configuration from {absolute_config_path}: {e}. Using default settings.")

def download_blocklist():
    global BLOCKLIST
    print(f"Attempting to download blocklist from {CONFIG['BLOCKLIST_URL']}...")
    try:
        response = requests.get(CONFIG['BLOCKLIST_URL'], timeout=10)
        response.raise_for_status() # Raise an exception for HTTP errors
        new_blocklist = set()
        for line in response.text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            parts = line.split()
            if len(parts) >= 2 and (parts[0] == '0.0.0.0' or parts[0] == '127.0.0.1'):
                domain = parts[1].strip().lower()
                if domain:
                    new_blocklist.add(domain)
            elif len(parts) == 1: # Just a domain on a line
                domain = parts[0].strip().lower()
                if domain:
                    new_blocklist.add(domain)

        with list_lock:
            BLOCKLIST = new_blocklist
        print(f"Blocklist downloaded and updated. {len(BLOCKLIST)} domains loaded.")
    except requests.exceptions.RequestException as e:
        print(f"Error downloading blocklist: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
    except Exception as e:
        print(f"Error processing blocklist: {e}", file=sys.stderr)
        traceback.print_exc()

def is_domain_blocked_hierarchical(qname, denylist, allowlist, blocklist):
    """
    Checks if a domain or any of its parent domains are in the DENYLIST, ALLOWLIST, or BLOCKLIST.
    Returns the action taken ("DENYLIST", "ALLOWLIST", "BLOCKLIST") and the matched domain,
    or (None, None) if no match.
    """
    parts = qname.split('.')
    # Iterate from the full domain to its parent domains (e.g., a.b.c.com -> b.c.com -> c.com)
    for i in range(len(parts)):
        sub_domain = ".".join(parts[i:])
        
        # Check DENYLIST first (highest priority for blocking)
        if sub_domain in denylist:
            return "DENYLIST", sub_domain
        
        # Check ALLOWLIST (overrides blocklist)
        if sub_domain in allowlist:
            return "ALLOWLIST", sub_domain
            
        # Check BLOCKLIST
        if sub_domain in blocklist:
            return "BLOCKLIST", sub_domain
            
    return None, None # Not blocked or allowed by any list

def refresh_blocklist_periodically():
    download_blocklist()
    threading.Timer(CONFIG['BLOCKLIST_REFRESH_INTERVAL'], refresh_blocklist_periodically).start()
    print(f"Next blocklist refresh scheduled in {CONFIG['BLOCKLIST_REFRESH_INTERVAL']} seconds.")


def dns_response(data, addr):
    global total_queries, blocked_queries
    try:
        request = message.from_wire(data)
    except exception.DNSException as e:
        print(f"Error parsing DNS request from {addr[0]}: {e}")
        return None # Invalid DNS query, drop it

    if not request.question:
        # Not a standard query, ignore
        return None

    qname_obj = request.question[0].name
    qname = qname_obj.to_text(omit_final_dot=True).lower()
    qtype = request.question[0].rdtype

    log_entry = f"{time.strftime('%H:%M:%S')} - Query from {addr[0]} for {qname} (Type: {rdatatype.to_text(qtype)})"
    with stats_lock:
        total_queries += 1
        dns_logs.append(log_entry)
    print(log_entry)

    def create_sinkhole_response(req, qname_to_block):
        response = message.make_response(req)
        response.set_rcode(0) # NOERROR
        answer = rrset.from_text(f'{qname_to_block}.', 60, 'IN', 'A', CONFIG['SINKHOLE_IP'])
        response.answer.append(answer)
        return response.to_wire()
    
    action, matched_domain = is_domain_blocked_hierarchical(qname, DENYLIST, ALLOWLIST, BLOCKLIST)
    
    # Initialize log_reason to be used in forwarding
    log_reason = ""
    was_blocked = False

    if action == "DENYLIST":
        with stats_lock:
            blocked_queries += 1
            log_entry = f"{time.strftime('%H:%M:%S')} - DENYLIST BLOCKED: {qname} (matched {matched_domain})"
            dns_logs.append(log_entry)
        print(log_entry)
        return create_sinkhole_response(request, qname)

    if action == "ALLOWLIST":
        log_reason = f" (matched {matched_domain}, overriding deny/block lists)"
        # Fall through to forwarding logic
    elif action == "BLOCKLIST":
        with stats_lock:
            blocked_queries += 1
            log_entry = f"{time.strftime('%H:%M:%S')} - BLOCKLIST BLOCKED: {qname} (matched {matched_domain})"
            dns_logs.append(log_entry)
        print(log_entry)
        return create_sinkhole_response(request, qname)

    # Forward the query to the upstream DNS server
    try:
        response = query.udp(request, CONFIG['UPSTREAM_DNS'], timeout=5)
        log_entry = f"{time.strftime('%H:%M:%S')} - FORWARDED: {qname} to {CONFIG['UPSTREAM_DNS']}{log_reason}"
        with stats_lock:
            dns_logs.append(log_entry)
        print(log_entry)
        return response.to_wire()
    except exception.Timeout:
        log_entry = f"{time.strftime('%H:%M:%S')} - TIMEOUT: Forwarding {qname} to {CONFIG['UPSTREAM_DNS']}{log_reason}"
        with stats_lock:
            dns_logs.append(log_entry)
        print(log_entry)
        response = message.make_response(request)
        response.set_rcode(2) # SERVFAIL
        return response.to_wire()
    except Exception as e:
        log_entry = f"{time.strftime('%H:%M:%S')} - ERROR: Forwarding DNS query for {qname}: {e}{log_reason}"
        with stats_lock:
            dns_logs.append(log_entry)
        print(log_entry)
        response = message.make_response(request)
        response.set_rcode(2) # SERVFAIL
        return response.to_wire()

def dns_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((CONFIG['DNS_HOST'], CONFIG['DNS_PORT']))
        print(f"DNS server listening on {CONFIG['DNS_HOST']}:{CONFIG['DNS_PORT']}")
    except PermissionError:
        print(f"Permission denied: Cannot bind to port {CONFIG['DNS_PORT']}. Please run with administrator/root privileges.")
        return
    except Exception as e:
        print(f"Failed to bind DNS server: {e}")
        return

    def handle_query(data, addr):
        response_data = dns_response(data, addr)
        if response_data:
            sock.sendto(response_data, addr)

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            threading.Thread(target=handle_query, args=(data, addr)).start()
        except Exception as e:
            print(f"An error occurred in the DNS server loop: {e}")

# Web Dashboard Routes
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/api/stats')
def get_stats():
    with stats_lock:
        with list_lock:
            stats = {
                'total_queries': total_queries,
                'blocked_queries': blocked_queries,
                'blocklist_size': len(BLOCKLIST),
                'allowlist': sorted(list(ALLOWLIST)),
                'denylist': sorted(list(DENYLIST))
            }
    return jsonify(stats)

@app.route('/api/logs')
def get_logs():
    with stats_lock:
        return jsonify({'logs': list(dns_logs)[::-1]})

@app.route('/api/allowlist', methods=['POST'])
def update_allowlist():
    data = request.get_json()
    domains = set(d.lower() for d in data.get('domains', []))
    with list_lock:
        global ALLOWLIST
        ALLOWLIST = domains
    return jsonify({"status": "success", "message": f"Allowlist updated with {len(ALLOWLIST)} domains."})

@app.route('/api/denylist', methods=['POST'])
def update_denylist():
    data = request.get_json()
    domains = set(d.lower() for d in data.get('domains', []))
    with list_lock:
        global DENYLIST
        DENYLIST = domains
    return jsonify({"status": "success", "message": f"Denylist updated with {len(DENYLIST)} domains."})

def run_web_dashboard():
    print(f"Web dashboard starting on http://0.0.0.0:{CONFIG['WEB_DASHBOARD_PORT']}")
    app.run(host='0.0.0.0', port=CONFIG['WEB_DASHBOARD_PORT'], debug=False)

if __name__ == "__main__":
    load_config()
    download_blocklist()
    refresh_blocklist_periodically()

    dashboard_thread = threading.Thread(target=run_web_dashboard)
    dashboard_thread.daemon = True
    dashboard_thread.start()

    print("\nStarting DNS server...")
    dns_server()
