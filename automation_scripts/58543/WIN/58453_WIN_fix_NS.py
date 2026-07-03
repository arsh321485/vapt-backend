import subprocess
import winreg

print("Enabling Network Level Authentication (NLA)...")

# Method 1 - Registry fix
try:
    key = winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
        0,
        winreg.KEY_SET_VALUE
    )
    # 1 = NLA required, 0 = NLA not required
    winreg.SetValueEx(key, "UserAuthentication", 0, winreg.REG_DWORD, 1)
    winreg.SetValueEx(key, "SecurityLayer", 0, winreg.REG_DWORD, 2)
    winreg.CloseKey(key)
    print("✅ Registry updated — NLA Enabled!")
except Exception as e:
    print(f"❌ Registry failed: {e}")

# Method 2 - Command line backup fix
try:
    subprocess.run([
        "reg", "add",
        r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
        "/v", "UserAuthentication",
        "/t", "REG_DWORD",
        "/d", "1",
        "/f"
    ], check=True)
    print("✅ Command line fix applied!")
except Exception as e:
    print(f"❌ Command fix failed: {e}")

print("\nAll done! Restarting in 10 seconds...")
subprocess.run(["shutdown", "/r", "/t", "10"])