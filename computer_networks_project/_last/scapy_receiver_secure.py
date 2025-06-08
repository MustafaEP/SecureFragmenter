from scapy.all import *  # Scapy kütüphanesi: paket dinleme ve analiz için
from collections import defaultdict  # Otomatik sözlük yapısı (iç içe dict için)
from Crypto.Cipher import AES  # AES şifre çözme işlemi
from Crypto.Util.Padding import unpad  # AES blok şifre çözme sonrası padding kaldırma
from hashlib import sha256  # SHA-256 hash doğrulama için

# Ortak anahtar (şifreleme ve çözme için)
KEY = b'Sixteen byte key'

# Tüm fragment'ları IP ID'ye göre gruplayacağımız yapı
fragments = defaultdict(dict)

# Her IP ID için "son fragment alındı mı?" bilgisini tutar
received_flags = {}

# IP ID ile ilişkili IV (Initialization Vector) saklanır
iv_storage = {}

# Her alınan pakette çalışacak fonksiyon
def packet_handler(pkt):
    # Paket hem IP hem de UDP katmanına sahip olmalı
    if IP in pkt and UDP in pkt:
        # Sadece belirli UDP portuna gelen paketleri işle (port 12345)
        if pkt[UDP].dport != 12345:
            return

        # IP ID değeri alınır (aynı dosya için tüm fragment'larda aynı olur)
        ip_id = pkt[IP].id

        # Fragment offset değeri alınır
        offset = pkt[IP].frag

        # More Fragments (MF) bayrağı alınır
        mf_flag = pkt[IP].flags

        # Veri yükü alınır (eğer varsa)
        data = bytes(pkt[Raw].load) if Raw in pkt else b''

        # İlk fragment'ta IV bilgisini ayıkla ve sakla
        if offset == 0:
            iv = data[:16]  # İlk 16 byte IV
            iv_storage[ip_id] = iv
            data = data[16:]  # Geriye kalan veri şifreli veri

        # Fragment, IP ID ve offset'e göre kaydedilir
        fragments[ip_id][offset] = data

        # Eğer bu son fragment ise, bunu kaydet
        if mf_flag == 0:
            received_flags[ip_id] = True

        # Eğer tüm fragment'lar geldiyse çözümlemeye geç
        if ip_id in received_flags:
            all_frags = fragments[ip_id]

            # Beklenen fragment sayısı = en büyük offset + 1
            expected = max(all_frags.keys()) + 1

            # Gerçekten hepsi geldiyse
            if len(all_frags) == expected:
                print("Tüm şifreli fragment'lar alındı. Çözülüyor...")

                # Fragment'lar offset sırasına göre birleştirilir
                full_data = b''.join([all_frags[i] for i in sorted(all_frags)])

                # IV alınır
                iv = iv_storage.get(ip_id)

                # IV bulunamazsa çözümleme yapılamaz
                if iv is None:
                    print("IV bulunamadı, deşifre edilemez!")
                    return

                # AES CBC çözümleyici tanımlanır
                cipher = AES.new(KEY, AES.MODE_CBC, iv)

                # Veriyi çöz (unpad işlemiyle birlikte)
                decrypted = unpad(cipher.decrypt(full_data), AES.block_size)

                # İlk 32 byte hash, kalan veri dosyanın kendisidir
                received_hash = decrypted[:32]
                original_data = decrypted[32:]

                # Dosyadan elde edilen hash yeniden hesaplanır
                calculated_hash = sha256(original_data).digest()

                # Hash karşılaştırması yapılır
                if received_hash == calculated_hash:
                    print("SHA-256 bütünlüğü doğrulandı.")
                    # Dosya başarılıysa kaydedilir
                    with open("reassembled_secure.txt", "wb") as f:
                        f.write(original_data)
                    print("Dosya yazıldı: reassembled_secure.txt")
                else:
                    print("Hash doğrulama başarısız!")

                # Bellekteki geçici veriler temizlenir
                del fragments[ip_id]
                del received_flags[ip_id]
                del iv_storage[ip_id]

# Scapy ile 'lo' arayüzünden paket dinleme başlatılır
print("Dinleniyor (iface='lo')...")
sniff(prn=packet_handler, iface="lo")

