from scapy.all import *

target_ip = "127.0.0.1"
icmp_pkt = IP(dst=target_ip)/ICMP()
send_time = time.time()
reply = sr1(icmp_pkt, timeout=2, verbose=0)
receive_time = time.time()

if reply:
    rtt = (receive_time - send_time) * 1000  # ms cinsinden
    print(f"RTT: {rtt:.2f} ms")
else:
    print("Hedefe ulaşamadı.")

