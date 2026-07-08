from collections import defaultdict
from time import time

ATTACK_LOG = defaultdict(lambda: defaultdict(list))
BLOCKED_IPS = {}

WINDOW_SECONDS = 60 * 60
MAX_ATTACK_ATTEMPTS = 3
BLOCK_DURATION = 30 * 60

def reset_rate_limiter():
    ATTACK_LOG.clear()
    BLOCKED_IPS.clear()

def is_ip_blocked(ip):
    current_time = time()

    if ip in BLOCKED_IPS:
        expiry = BLOCKED_IPS[ip]
        if current_time < expiry:
            return True, int(expiry - current_time)
        else:
            del BLOCKED_IPS[ip]

    return False, 0

def check_and_update_attack_limit(ip, attack_type):
    current_time = time()

    blocked, remaining = is_ip_blocked(ip)
    if blocked:
        return True, remaining, 0

    ATTACK_LOG[ip][attack_type] = [
        t for t in ATTACK_LOG[ip][attack_type]
        if current_time - t < WINDOW_SECONDS
    ]

    ATTACK_LOG[ip][attack_type].append(current_time)
    attack_count = len(ATTACK_LOG[ip][attack_type])

    if attack_count > MAX_ATTACK_ATTEMPTS:
        BLOCKED_IPS[ip] = current_time + BLOCK_DURATION
        return True, BLOCK_DURATION, attack_count

    return False, 0, attack_count

def get_ip_stats():
    result = {}
    for ip, attacks in ATTACK_LOG.items():
        result[ip] = {attack: len(times) for attack, times in attacks.items()}
    return result

def get_blocked_ips():
    current_time = time()
    active_blocks = {}

    for ip, expiry in list(BLOCKED_IPS.items()):
        if current_time < expiry:
            active_blocks[ip] = int(expiry - current_time)
        else:
            del BLOCKED_IPS[ip]

    return active_blocks