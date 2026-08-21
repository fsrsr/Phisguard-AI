import subprocess
import os
import sys
import urllib.request
import json

# Konfigurasi: Lokasi Tshark
def get_tshark_path():
    # 1. Cek di PATH
    from shutil import which
    path = which("tshark")
    if path: return path
    
    # 2. Cek lokasi standar Windows
    common_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        os.path.join(os.environ.get("USERPROFILE", ""), r"Documents\Wireshark\tshark.exe"),
        r"C:\Users\Defen\Documents\Wireshark\tshark.exe" # Original path fallback
    ]
    for p in common_paths:
        if os.path.exists(p):
            return p
    return "tshark" # Default to PATH if nothing found

TSHARK_PATH = get_tshark_path()
MANUAL_INTERFACE_ID = None

# Prefix IP Server Meta/Relay untuk disaring agar hasil lebih bersih [3]
META_PREFIXES = [
    "157.240.", "31.13.", "173.252.", "129.134.", 
    "185.60.", "192.169.", "57.144.", "36.91.",
    "179.60."
]

def get_ip_info(ip):
    """Mendapatkan informasi IP (ISP, Negara, Kota, ASN, dll)."""
    try:
        # Request field tambahan: status, message, country, city, zip, lat, lon, isp, org, as, reverse, hosting, proxy
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,zip,lat,lon,isp,org,as,reverse,hosting,proxy"
        
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            if data.get('status') == 'success':
                # Mapping data ke format yang diminta
                # Note: 'RDAP Netblock' dan 'RDAP Name' spesifik membutuhkan query WHOIS/RDAP yang berat.
                # Kita gunakan Org/AS sebagai pendekatan yang paling dekat dan cepat.
                
                # Deteksi VPN/Hosting
                is_vpn = data.get('hosting') or data.get('proxy')
                type_label = "[!] TIPE: VPN/DATACENTER/PROXY" if is_vpn else "Tipe: ISP Perumahan/Seluler (Asli)"

                info = (
                    f"\n    │  ├── {type_label}"
                    f"\n    │  ├── Provider : {data.get('isp', 'Unknown')}"
                    f"\n    │  ├── ASN      : {data.get('as', 'Unknown')}"
                    f"\n    │  ├── Org      : {data.get('org', 'Unknown')} (RDAP Name approx)"
                    f"\n    │  ├── Domain   : {data.get('reverse', 'Unknown')} (Reverse DNS)"
                    f"\n    │  ├── Kota     : {data.get('city', 'Unknown')}"
                    f"\n    │  ├── Negara   : {data.get('country', 'Unknown')}"
                    f"\n    │  ├── Kode Pos : {data.get('zip', 'Unknown')}"
                    f"\n    │  └── Koordinat: {data.get('lat')}, {data.get('lon')}"
                )
                return info
    except Exception as e:
        print(f"[!] Gagal lookup IP {ip}: {e}", flush=True)
        return None
    return None
def is_ignored(ip):
    if not ip or ip == "": return True
    # Abaikan IP lokal (Private Network)
    if ip.startswith(("192.168.", "10.", "172.16.", "127.", "169.254.")):
        return True
    # Abaikan IP Infrastruktur Meta
    return any(ip.startswith(prefix) for prefix in META_PREFIXES)

def get_best_interface():
    """Mendeteksi interface terbaik (Wi-Fi/Ethernet) secara otomatis."""
    # print("[*] Mendeteksi interface jaringan...", flush=True)
    try:
        # Menjalankan tshark -D untuk list interface
        proc = subprocess.run([TSHARK_PATH, "-D"], capture_output=True, text=True)
        if proc.returncode != 0:
            return None
        
        interfaces = proc.stdout.splitlines()
        wifi_idx = None
        ethernet_idx = None
        
        for line in interfaces:
            # Format output: "1. \Device\NPF_... (Wi-Fi)"
            parts = line.split(". ", 1)
            if len(parts) < 2: continue
            
            idx = parts[0]
            name = parts[1]
            
            if "Wi-Fi" in name:
                wifi_idx = idx
            elif "Ethernet" in name:
                ethernet_idx = idx

        # Prioritas: Wi-Fi > Ethernet
        selected = wifi_idx if wifi_idx else ethernet_idx
        
        if selected:
            # Cari nama interface untuk display
            for line in interfaces:
                if line.startswith(f"{selected}."):
                    # print(f"[*] Interface terpilih: {line}", flush=True)
                    break
            return selected
            
    except Exception as e:
        print(f"[!] Gagal mendeteksi interface: {e}")
    
    return None

def run_sniffer():
    # Detect interface automatically
    selected_interface = None
    
    if MANUAL_INTERFACE_ID:
        print(f"[*] Menggunakan interface manual: {MANUAL_INTERFACE_ID}")
        selected_interface = MANUAL_INTERFACE_ID
    else:
        selected_interface = get_best_interface()
    
    # Fallback/Validation
    if not selected_interface:
        print(f"[!] Auto-detect gagal dan tidak ada MANUAL_INTERFACE_ID.")
        return
    else:
        active_interface = selected_interface

    # Command tshark lengkap berdasarkan referensi Anda
    # -l: flush output secara real-time agar Python bisa membaca baris demi baris segera
    # -n: mematikan resolusi nama DNS untuk kecepatan maksimal
    cmd = [
        TSHARK_PATH, "-i", active_interface,
        "-n", "-l",
        "-Y", "stun",
        "-T", "fields",
        "-e", "ip.src", 
        "-e", "ip.dst", 
        "-e", "classicstun.att.ipv4",
        "-e", "stun.att.ipv4",
        "-e", "classicstun.att.ipv4-xord"
    ]

    # print(f"[*] Sniffer aktif pada interface {active_interface}...", flush=True)
    # print("[*] Pastikan 'Protect IP Address in Calls' di WhatsApp HP sudah OFF.")
    print("[*] Menunggu panggilan dilakukan/diterima...")
    # print("-" * 70)

    unique_ips = set()
    process = None

    try:
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True,
            bufsize=1 
        )

        # Membaca output Tshark secara real-time
        for line in iter(process.stdout.readline, ""):
            parts = line.strip().split("\t")
            
            if len(parts) >= 2:
                src = parts[0]
                dst = parts[1]
                
                # Cek field STUN yang mungkin berisi IP publik
                stun_ip = None
                if len(parts) > 2:
                    # Gabungkan semua field STUN yang tertangkap
                    for field in parts[2:]:
                        if field and not is_ignored(field):
                            stun_ip = field
                            break

                # KATEGORISASI IP
                label = ""
                detected_ip = None

                # 1. Jika source adalah Meta/Lokal
                if is_ignored(src):
                    # Cek jika destination adalah Peer (Outgoing Traffic)
                    if not is_ignored(dst):
                        label = "TARGET: IP Lawan (Outgoing)"
                        detected_ip = dst
                    
                    # Cek jika destination adalah Relay (Meta) - Sembunyikan lagi sesuai request
                    elif any(dst.startswith(prefix) for prefix in META_PREFIXES):
                        pass
                        # label = "INFO: Terhubung ke Relay Server (Meta)"
                        # detected_ip = dst
                    
                    # Cek STUN (NAT detection)
                    elif stun_ip and not is_ignored(stun_ip):
                        pass
                        # label = "NOTE: IP Publik Anda (NAT)"
                        # detected_ip = stun_ip
                    
                    # Tambahan Debug: Cek apakah Relay (Meta) atau Lokal
                    elif src not in unique_ips:
                        if src.startswith(("192.168.", "10.", "172.16.", "127.")):
                            pass # Jangan spam traffic lokal jika sudah terdeteksi di atas
                            # print(f"[*] Terdeteksi Traffic Lokal (LAN/WiFi): {src}", flush=True)
                        else:
                            pass
                            # Source adalah Meta (Incoming dari Relay)
                            # label = "INFO: Data Masuk dari Relay (Meta)"
                            # detected_ip = src

                        unique_ips.add(src)
                
                # 2. Jika source BUKAN Meta dan BUKAN lokal => Kemungkinan besar Peer (Incoming)
                
                # 2. Jika source BUKAN Meta dan BUKAN lokal => Kemungkinan besar Peer
                elif not is_ignored(src):
                    label = "TARGET: IP Lawan (Incoming)"
                    detected_ip = src

                # End of logic


                # Tampilkan hasil
                if detected_ip and detected_ip not in unique_ips:
                    print(f"[!] {label}: {detected_ip}", flush=True)
                    
                    # IP Lookup (Target Lawan / NAT Public / Relay)
                    if "TARGET" in label or "NAT" in label or "INFO" in label:
                        info = get_ip_info(detected_ip)
                        if info:
                            print(f"    └─ Info: {info}", flush=True)

                    unique_ips.add(detected_ip)

        # Wait for process to exit
        return_code = process.wait()
        out, err = process.communicate()
        print(f"[!] TShark exited with code {return_code}")
        if err:
             print(f"[!] TShark Output:\n{err}")
             if err:
                 print(f"[!] TShark Output:\n{err}")

    except KeyboardInterrupt:
        print("\n[*] Monitoring dihentikan oleh pengguna.")
        if process:
            process.terminate()
    except FileNotFoundError:
        print("[!] Tshark tidak ditemukan. Pastikan folder Wireshark sudah masuk ke System PATH.")
    except Exception as e:
        print(f"[!] Terjadi kesalahan: {e}")

if __name__ == "__main__":
    run_sniffer()