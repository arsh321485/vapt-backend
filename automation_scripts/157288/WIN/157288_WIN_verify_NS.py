import socket, ssl

host = "YOUR_VM_IP"
port = 10056

print("Checking TLS 1.1...")

try:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_1
    ctx.maximum_version = ssl.TLSVersion.TLSv1_1

    with socket.create_connection((host, port), timeout=5) as s:
        with ctx.wrap_socket(s):
            print("❌ TLS 1.1 still ON — fix did not work!")
except:
    print("✅ TLS 1.1 is OFF — Fix successful!")