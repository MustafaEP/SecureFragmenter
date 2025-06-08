#scapy_sender.py
from scapy.all import *
import math

# 📄 Göndermek istediğin dosya
file_path = "test_file.txt"
dst_ip = "127.0.0.1"  # localhost
dst_port = 12345      # UDP hedef port

# 📤 Fragment ayarları
FRAG_SIZE = 1480  # Maksimum payload boyutu (MTU altında kalması için)

# 📚 Dosyayı oku
with open(file_path, "rb") as f:
    file_data = f.read()

# 📦 Kaç fragment'e bölünecek?
num_frags = math.ceil(len(file_data) / FRAG_SIZE)
print(f"🚀 Dosya {num_frags} parçaya bölünecek.")

# 🔁 Fragment'ları sırayla gönder
for i in range(num_frags):
    start = i * FRAG_SIZE
    end = start + FRAG_SIZE
    chunk = file_data[start:end]

    mf_flag = 1 if i < num_frags - 1 else 0  # More Fragments flag
    frag_offset = i                         # Fragment offset (8-byte units, burada 1=1 parça kabul)

    ip_pkt = IP(dst=dst_ip, id=1001, flags=mf_flag, frag=frag_offset) / \
             UDP(dport=dst_port, sport=54321) / \
             Raw(load=chunk)

    send(ip_pkt)
    print(f"📦 Fragment gönderildi → {i+1}/{num_frags} (Offset={frag_offset}, MF={mf_flag})")

print("✅ Tüm fragment'lar gönderildi.")

