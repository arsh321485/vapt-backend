# import subprocess

# # Run this on your LAPTOP
# # It tries to connect without NLA — should fail if fixed

# host = "YOUR_VM_IP"  # ← replace this

# result = subprocess.run(
#     ["powershell", "-Command",
#      f"Test-NetConnection -ComputerName {host} -Port 10056"],
#     capture_output=True, text=True
# )

# print("Connection test done!")
# print("Now check Nessus scan to confirm NLA is enforced ✅")



import winreg

print("Checking if NLA is enabled on this VM...\n")

try:
    key = winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    )
    
    user_auth, _ = winreg.QueryValueEx(key, "UserAuthentication")
    security_layer, _ = winreg.QueryValueEx(key, "SecurityLayer")
    winreg.CloseKey(key)

    print(f"UserAuthentication value: {user_auth}")
    print(f"SecurityLayer value: {security_layer}\n")

    if user_auth == 1 and security_layer == 2:
        print("✅ NLA is ENABLED — Fix successful!")
    else:
        print("❌ NLA is NOT enabled — Run fix again!")

except Exception as e:
    print(f"❌ Error: {e}")