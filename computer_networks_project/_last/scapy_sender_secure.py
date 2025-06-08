from scapy.all import *  # Scapy kütüphanesi: düşük seviyeli ağ paketi oluşturma ve gönderme
from Crypto.Cipher import AES  # AES şifreleme sınıfı
from Crypto.Util.Padding import pad  # AES blok şifreleme için veri pad fonksiyonu
from hashlib import sha256  # SHA-256 hash fonksiyonu
import math  # Matematik işlemleri (özellikle tavan alma için)

# Ortak sabit anahtar (16 byte = 128 bit)
KEY = b'Sixteen byte key'

# Gönderilecek dosya yolu
file_path = "test_file.txt"

# Hedef IP adresi ve UDP portu
dst_ip = "127.0.0.1"
dst_port = 12345

# Her fragment boyutu (UDP/IP sınırlarına göre belirlenmiş)
FRAG_SIZE = 1480

# Dosyayı ikili (binary) modda oku
with open(file_path, "rb") as f:
    file_data = f.read()

# Dosyanın SHA-256 hash'ini hesapla (bütünlük kontrolü için)
file_hash = sha256(file_data).digest()

# AES CBC modunda şifreleme objesi oluştur (rastgele IV otomatik atanır)
cipher = AES.new(KEY, AES.MODE_CBC)

# AES CBC IV (Initialization Vector) alınır
iv = cipher.iv

# Dosyanın başına hash'i ekle, sonra pad edilerek AES bloğuna uygun hale getirilir
padded_data = pad(file_hash + file_data, AES.block_size)

# Şifreli veri oluşturulur
encrypted_data = cipher.encrypt(padded_data)

# Şifreli veriyi fragmentlara ayırmak için toplam fragment sayısını hesapla
num_frags = math.ceil(len(encrypted_data) / FRAG_SIZE)

print(f"Şifreli veri {num_frags} parçaya bölünüyor.")

# Her bir fragment için döngü başlatılır
for i in range(num_frags):
    # Fragment'ın başlangıç ve bitiş byte'larını belirle
    start = i * FRAG_SIZE
    end = start + FRAG_SIZE
    chunk = encrypted_data[start:end]

    # "More Fragments" bayrağı: son fragment değilse 1, son ise 0
    mf_flag = 1 if i < num_frags - 1 else 0

    # Fragment offset değeri (IP katmanında kullanılır)
    frag_offset = i

    # IP/UDP/Raw payload ile paket oluştur
    # İlk pakette IV eklenir; sonraki paketler sadece şifreli chunk içerir
    ip_pkt = IP(dst=dst_ip, id=2002, flags=mf_flag, frag=frag_offset) / \
             UDP(dport=dst_port, sport=54321) / \
             Raw(load=(iv if i == 0 else b'') + chunk)

    # Paketi gönder
    send(ip_pkt)

    # Gönderilen fragment hakkında bilgi yazdır
    print(f"Şifreli fragment gönderildi: {i+1}/{num_frags} (Offset={frag_offset}, MF={mf_flag})")

# Tüm paketler gönderildiğinde kullanıcıya bildirim ver
print("Şifreli dosya gönderildi.")

