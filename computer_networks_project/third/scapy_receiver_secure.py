from scapy.all import *
from collections import defaultdict
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256

KEY = b'Sixteen byte key'
fragments = defaultdict(dict)
received_flags = {}
iv_storage = {}  # <--- IV'leri IP ID ile eşle

def packet_handler(pkt):
    if IP in pkt and UDP in pkt:
        if pkt[UDP].dport != 12345:
            return

        ip_id = pkt[IP].id
        offset = pkt[IP].frag
        mf_flag = pkt[IP].flags
        data = bytes(pkt[Raw].load) if Raw in pkt else b''

        if offset == 0:
            iv = data[:16]
            iv_storage[ip_id] = iv  # <--- IV'yi sakla
            data = data[16:]

        fragments[ip_id][offset] = data
        if mf_flag == 0:
            received_flags[ip_id] = True

        # Tüm parçalar geldiyse
        if ip_id in received_flags:
            all_frags = fragments[ip_id]
            expected = max(all_frags.keys()) + 1
            if len(all_frags) == expected:
                print("Tüm şifreli fragment'lar alındı. Çözülüyor...")

                full_data = b''.join([all_frags[i] for i in sorted(all_frags)])
                iv = iv_storage.get(ip_id)

                if iv is None:
                    print("IV bulunamadı, deşifre edilemez!")
                    return

                cipher = AES.new(KEY, AES.MODE_CBC, iv)
                decrypted = unpad(cipher.decrypt(full_data), AES.block_size)

                received_hash = decrypted[:32]
                original_data = decrypted[32:]

                calculated_hash = sha256(original_data).digest()
                if received_hash == calculated_hash:
                    print(" SHA-256 bütünlüğü doğrulandı.")
                    with open("reassembled_secure.txt", "wb") as f:
                        f.write(original_data)
                    print(" Dosya yazıldı: reassembled_secure.txt")
                else:
                    print(" Hash doğrulama başarısız!")

                # Temizlik
                del fragments[ip_id]
                del received_flags[ip_id]
                del iv_storage[ip_id]

print("🎧 Dinleniyor (iface='lo')...")
sniff(prn=packet_handler, iface="lo")

