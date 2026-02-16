"""
TLS 1.3 Client Example using Python's ssl module
"""

import ssl
import socket

hostname = 'www.google.com'  # Example server
port = 443

# Step 1: Create an SSL context for TLS 1.3
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.check_hostname = True
context.verify_mode = ssl.CERT_REQUIRED

# Step 2: Load default CA certificates
context.load_default_certs()

# Step 3: Create a TCP connection and wrap it in TLS
with socket.create_connection((hostname, port)) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
        print("TLS version:", tls_sock.version())
        print("Cipher suite:", tls_sock.cipher())
        print("Server certificate:", tls_sock.getpeercert())
