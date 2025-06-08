import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from hashlib import sha256

# AES anahtarı ve IV oluştur
aes_key = get_random_bytes(32)
iv = get_random_bytes(16)

# Dosyayı oku
with open('test_file.txt', 'rb') as f:
    plaintext = f.read()

# SHA-256 ile hash oluştur
file_hash = sha256(plaintext).digest()

# AES ile şifrele
def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
ciphertext = cipher_aes.encrypt(pad(plaintext))

# Sunucunun açık anahtarını oku ve AES anahtarını şifrele
with open('public.pem', 'rb') as f:
    public_key = RSA.import_key(f.read())

cipher_rsa = PKCS1_OAEP.new(public_key)
encrypted_key = cipher_rsa.encrypt(aes_key + iv)

# TCP ile gönder
s = socket.socket()
s.connect(('127.0.0.1', 9090))

# Veri = RSA(encrypted_key+iv) + SHA256 + ciphertext
s.sendall(encrypted_key + file_hash + ciphertext)
s.close()

print("RSA ile şifrelenmiş dosya gönderildi.")
