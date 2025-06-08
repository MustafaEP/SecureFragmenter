#scapy_receiver.py
from scapy.all import *
from collections import defaultdict

fragments = defaultdict(dict)   # { ip_id: { offset: data } }
received_flags = {}             # ip_id: mf_flag

def packet_handler(pkt):
    if IP in pkt and UDP in pkt:
        if pkt[UDP].dport != 12345:
            return

        ip_id = pkt[IP].id
        frag_offset = pkt[IP].frag
        mf_flag = pkt[IP].flags
        data = bytes(pkt[Raw].load) if Raw in pkt else b""

        print(f"📦 Fragment alındı → ID={ip_id}, Offset={frag_offset}, MF={mf_flag}, Len={len(data)}")

        fragments[ip_id][frag_offset] = data
        if mf_flag == 0:
            received_flags[ip_id] = True

        # Tüm fragment'lar geldiyse birleştir
        if ip_id in received_flags:
            all_frags = fragments[ip_id]
            expected_count = max(all_frags.keys()) + 1

            if len(all_frags) == expected_count:
                print(f"✅ Tüm {expected_count} fragment alındı, birleştiriliyor...")

                full_data = b''.join([all_frags[i] for i in sorted(all_frags)])
                with open("reassembled.txt", "wb") as f:
                    f.write(full_data)

                print("✅ Dosya başarıyla oluşturuldu: reassembled.txt")

                del fragments[ip_id]
                del received_flags[ip_id]

print("🎧 Dinleniyor (iface='lo')...")
sniff(prn=packet_handler, iface="lo")

