import socket
import random
import time
import datetime

# --- Configuration ---
GRAYLOG_IP = "192.168.1.170"  # Graylog server IP
GRAYLOG_PORT = 5514          # UDP Syslog port
PFSENSE_HOSTNAME = "pfsense"

# --- Data for Randomization ---
PROTOCOLS = ["tcp", "udp"]
ACTIONS = ["pass", "block"]
DIRECTIONS = ["in", "out"]
INTERFACES = ["em0", "em1"]
INTERNAL_IP = "122.96.29.95"  # Fixed internal destination

# Normal external IPs
NORMAL_IPS_PREFIX = [
    "8.8.", "1.1.", "104.16.", "192.0."
]

# Suspicious/malicious IPs from various threat intelligence feeds
SUSPICIOUS_IPS = [
    # Original IPs
    "185.199.108.0", "45.55.212.1", "203.0.113.5",
    # Added from AbuseIPDB & other TI sources (as of late 2025)
    "103.141.141.22", "193.163.125.40", "179.43.145.148", "194.31.52.123",
    "103.137.12.213", "185.220.101.41", "185.220.101.147", "45.146.164.110",
    "185.244.25.232", "171.244.37.96", "139.226.28.201", "192.81.217.216",
    "180.100.206.94", "43.225.53.200", "203.190.53.154", "189.216.168.66",
    "199.45.154.179", "161.35.105.239", "74.241.242.73", "71.18.255.51"
]

def generate_random_ip(suspicious=False):
    """Generate a random external IP. Suspicious if flag is True."""
    if suspicious:
        return random.choice(SUSPICIOUS_IPS)
    else:
        prefix = random.choice(NORMAL_IPS_PREFIX)
        return prefix + str(random.randint(1, 254)) + "." + str(random.randint(1, 254))

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"--- Advanced pfSense Log Simulator ---")
    print(f"Target: {GRAYLOG_IP}:{GRAYLOG_PORT}. Press Ctrl+C to stop.")
    print("-" * 50)

    try:
        while True:
            protocol = random.choice(PROTOCOLS)
            # Increased weight for 'block' action for suspicious IPs
            is_suspicious = random.choices([True, False], weights=[0.2, 0.8], k=1)[0]
            
            if is_suspicious:
                action = "block"
            else:
                action = "pass"

            direction = random.choice(DIRECTIONS)
            interface = random.choice(INTERFACES)

            # --- Base Fields ---
            base_fields = [
                str(random.randint(3, 10)),          # RuleNumber
                str(random.randint(10000, 20000)),   # SubRuleNumber
                "",                                   # Anchor
                "16777216",                           # Tracker
                interface,                            # Interface
                "match",                              # Reason
                action,                               # Action
                direction,                            # Direction
                "4",                                  # IPVersion
            ]

            # --- Decide source and destination IPs ---
            if direction == "out":
                # Outbound traffic is less likely to be from a suspicious source in this model
                src_ip = INTERNAL_IP
                dst_ip = generate_random_ip()
            else:  # "in"
                src_ip = generate_random_ip(suspicious=is_suspicious)
                dst_ip = INTERNAL_IP

            # --- Protocol-Specific Fields ---
            if protocol == "tcp":
                protocol_fields = [
                    str(random.randint(0, 255)),        # TOS
                    "",                                 # ECN
                    str(random.randint(50, 128)),       # TTL
                    str(random.randint(1, 65535)),      # ID
                    "0",                                # Offset
                    "DF",                               # Flags
                    "6",                                # ProtocolID
                    "tcp",                              # Protocol
                    str(random.randint(60, 1500)),      # Length
                    src_ip,
                    dst_ip,
                    str(random.randint(1024, 65535)),   # SourcePort
                    str(random.choice([80, 443, 53, 22, 8080])),  # DestPort
                    str(random.randint(40, 1460)),      # DataLength
                    "S",                                # TCPFlags
                    str(random.randint(1000000, 9999999)),  # Sequence
                    "0",                                # ACK
                    str(random.randint(1024, 65535)),   # Window
                    "0",                                # URG
                    "",                                 # Options
                ]
            elif protocol == "udp":
                protocol_fields = [
                    str(random.randint(0, 255)),        # TOS
                    "",                                 # ECN
                    str(random.randint(50, 128)),       # TTL
                    str(random.randint(1, 65535)),      # ID
                    "0",                                # Offset
                    "",                                 # Flags
                    "17",                               # ProtocolID
                    "udp",                              # Protocol
                    str(random.randint(28, 1500)),      # Length
                    src_ip,
                    dst_ip,
                    str(random.randint(1024, 65535)),   # SourcePort
                    str(random.choice([53, 123, 161, 5060])),  # DestPort
                    str(random.randint(8, 1472)),       # DataLength
                ]

            message_body = ",".join(base_fields + protocol_fields)

            # --- Build Syslog message ---
            now = datetime.datetime.now()
            timestamp = now.strftime("%b %d %H:%M:%S")
            if timestamp[4] == '0':
                timestamp = timestamp[:4] + ' ' + timestamp[5:]

            pid_str = str(random.randint(10000, 99999)).zfill(5)
            full_syslog_message = f"<134>{timestamp} {PFSENSE_HOSTNAME} filterlog[{pid_str}]: {message_body}"

            # --- Send to Graylog ---
            sock.sendto(full_syslog_message.encode('utf-8'), (GRAYLOG_IP, GRAYLOG_PORT))
            print(f"Sent ({protocol.upper()}): {full_syslog_message}")

            time.sleep(random.uniform(0.5, 2.5))  # Random interval

    except KeyboardInterrupt:
        print("\nSimulator stopped by user.")
    finally:
        sock.close()

if __name__ == "__main__":
    main()

