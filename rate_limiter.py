from collections import defaultdict
from time import time

REQUEST_LOG = defaultdict(list)
WINDOW_SECONDS = 60
MAX_REQUESTS = 10

def is_rate_limited(ip):
    current_time = time()
    REQUEST_LOG[ip] = [t for t in REQUEST_LOG[ip] if current_time - t < WINDOW_SECONDS]
    REQUEST_LOG[ip].append(current_time)
    return len(REQUEST_LOG[ip]) > MAX_REQUESTS

def get_ip_stats():
    return {ip: len(times) for ip, times in REQUEST_LOG.items()}