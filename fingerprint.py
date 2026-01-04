import hashlib
from flask import request

def generate_fingerprint():
    ip = request.headers.get('X-Forwarded-For') or request.remote_addr or ''
    user_agent = request.headers.get('User-Agent', '')

    if ',' in ip:
        ip = ip.split(',')[0].strip()

    if ip.startswith('::ffff:'):
        ip = ip.split('::ffff:', 1)[1]
    if ip == '::1':
        ip = '127.0.0.1'

    fingerprint_string = f"{ip}{user_agent}"
    fingerprint = hashlib.sha256(fingerprint_string.encode('utf-8')).hexdigest()

    return fingerprint, ip

def get_client_ip():
    ip = request.headers.get('X-Forwarded-For') or request.remote_addr or ''
    if ',' in ip:
        ip = ip.split(',')[0].strip()
    if ip.startswith('::ffff:'):
        ip = ip.split('::ffff:', 1)[1]
    if ip == '::1':
        ip = '127.0.0.1'
    return ip
