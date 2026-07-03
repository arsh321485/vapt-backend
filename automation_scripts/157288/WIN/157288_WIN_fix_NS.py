import winreg
import subprocess

print("Disabling TLS 1.1...")

base = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

settings = {
    "TLS 1.1\\Server": {"Enabled": 0, "DisabledByDefault": 1},
    "TLS 1.1\\Client": {"Enabled": 0, "DisabledByDefault": 1},
}

for proto, vals in settings.items():
    try:
        key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE,
                                  f"{base}\\{proto}", 0, winreg.KEY_SET_VALUE)
        for k, v in vals.items():
            winreg.SetValueEx(key, k, 0, winreg.REG_DWORD, v)
        winreg.CloseKey(key)
        print(f"✅ Done: {proto}")
    except Exception as e:
        print(f"❌ Failed: {proto} - {e}")

print("\nAll done! Restarting in 10 seconds...")
subprocess.run(["shutdown", "/r", "/t", "10"])