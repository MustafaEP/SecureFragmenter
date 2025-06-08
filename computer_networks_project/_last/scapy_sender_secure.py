from scapy.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
import math

# 🛡️ Ortak sabit anahtar (16 byte = 128 bit)
KEY = b'Sixteen byte key'

file_path = "test_file.txt"
dst_ip = "127.0.0.1"
dst_port = 12345
FRAG_SIZE = 1480

# 📄 Dosyayı oku
with open(file_path, "rb") as f:
    file_data = f.read()

# 🔐 SHA-256 hash hesapla
file_hash = sha256(file_data).digest()

# 🔐 AES ile şifrele
cipher = AES.new(KEY, AES.MODE_CBC)
iv = cipher.iv
encrypted_data = cipher.encrypt(pad(file_hash + file_data, AES.block_size))

# 📦 Fragment'lara böl
num_frags = math.ceil(len(encrypted_data) / FRAG_SIZE)
print(f"🔐 Şifreli veri {num_frags} parçaya bölünüyor.")

for i in range(num_frags):
    start = i * FRAG_SIZE
    end = start + FRAG_SIZE
    chunk = encrypted_data[start:end]

    mf_flag = 1 if i < num_frags - 1 else 0
    frag_offset = i

    ip_pkt = IP(dst=dst_ip, id=2002, flags=mf_flag, frag=frag_offset) / \
             UDP(dport=dst_port, sport=54321) / \
             Raw(load=(iv if i == 0 else b'') + chunk)  # İlk pakete IV ekle

    send(ip_pkt)
    print(f"📦 Şifreli fragment gönderildi: {i+1}/{num_frags} (Offset={frag_offset}, MF={mf_flag})")

print("✅ Şifreli dosya gönderildi.")

