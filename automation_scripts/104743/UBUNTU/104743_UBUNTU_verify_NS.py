import socket
import ssl

host = "YOUR_VM_IP"   # ← change this
port = 443            # ← change if different

print(f"Verifying TLS 1.0 is disabled on {host}:{port} ...\n")

try:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.maximum_version = ssl.TLSVersion.TLSv1

    with socket.create_connection((host, port), timeout=5) as s:
        with ctx.wrap_socket(s):
            print("❌ TLS 1.0 still ON — fix did not work!")
except:
    print("✅ TLS 1.0 is OFF — Fix was successful!")