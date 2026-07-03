import socket
import ssl

host = "YOUR_VM_IP"   # ← change this
port = 443            # ← change if different (e.g. 10056, 8443)

print(f"{'='*55}")
print(f"  TLS 1.1 Verification Script — Ubuntu")
print(f"  Target : {host}:{port}")
print(f"{'='*55}\n")

try:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_1
    ctx.maximum_version = ssl.TLSVersion.TLSv1_1

    print("Attempting TLS 1.1 handshake...")

    with socket.create_connection((host, port), timeout=5) as s:
        with ctx.wrap_socket(s):
            print("❌ TLS 1.1 is still ENABLED — Fix did not work!")
            print("   → Check openssl.cnf or crypto-policies and retry.")

except ssl.SSLError as e:
    print(f"✅ TLS 1.1 is DISABLED — Fix was successful!")
    print(f"   SSL Error (expected): {e}")

except ConnectionRefusedError:
    print(f"⚠️  Connection refused on {host}:{port}")
    print("   → Check if the service is running and port is correct.")

except socket.timeout:
    print(f"⚠️  Connection timed out on {host}:{port}")
    print("   → Check firewall rules or if the host is reachable.")

except Exception as e:
    print(f"⚠️  Unexpected error: {e}")

print(f"\n{'='*55}")
print("  Verification Complete")
print(f"{'='*55}")