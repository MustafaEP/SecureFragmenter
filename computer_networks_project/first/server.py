import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from hashlib import sha256

# Unpad fonksiyonu
def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

# Sunucuyu başlat
server = socket.socket()
server.bind(('0.0.0.0', 9090))
server.listen(1)
print("Sunucu dinleniyor...")

conn, addr = server.accept()
print("Bağlantı geldi:", addr)

data = b""
while True:
    chunk = conn.recv(4096)
    if not chunk:
        break
    data += chunk
conn.close()

# Anahtar uzunluğu = 256 byte (RSA 2048), SHA256 = 32 byte
encrypted_key = data[:256]
recv_hash = data[256:288]
ciphertext = data[288:]

# RSA özel anahtarını yükle ve çöz
with open('private.pem', 'rb') as f:
    private_key = RSA.import_key(f.read())

cipher_rsa = PKCS1_OAEP.new(private_key)
decrypted = cipher_rsa.decrypt(encrypted_key)
aes_key = decrypted[:32]
iv = decrypted[32:]

# AES çöz
cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
plaintext = unpad(cipher_aes.decrypt(ciphertext))

# SHA-256 doğrulama
calc_hash = sha256(plaintext).digest()

if calc_hash == recv_hash:
    print("SHA-256 doğrulama başarılı. Dosya bütün.")
    with open("received_file.txt", "wb") as f:
        f.write(plaintext)
else:
    print("Uyarı: Bütünlük hatası! Hash uyuşmuyor.")

print("Dosya kaydedildi.")

