import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
# 1. Membuat kunci AES-256
key = AESGCM.generate_key(bit_length=256)

# 2. Membuat objek AES-GCM
aesgcm = AESGCM(key)

# 3. Menentukan plaintext
plaintext = "Ahmad Dava Rifa’i"
data = plaintext.encode("utf-8")

# 4. Membuat nonce sepanjang 12 byte
nonce = os.urandom(12)

# 5. Proses enkripsi
encrypted_data = aesgcm.encrypt(nonce, data, None)

# Memisahkan ciphertext dan authentication tag
ciphertext = encrypted_data[:-16]
tag = encrypted_data[-16:]

# 6. Proses dekripsi
decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
decrypted_text = decrypted_data.decode("utf-8")

# 7. Menampilkan hasil enkripsi
print("===== HASIL ENKRIPSI AES-256-GCM =====")
print("Plaintext          :", plaintext)
print("Ciphertext         :", ciphertext.hex())
print("Nonce              :", nonce.hex())
print("Authentication Tag :", tag.hex())

# 8. Menampilkan hasil dekripsi
print("\n===== HASIL DEKRIPSI =====")
print("Plaintext Hasil    :", decrypted_text)

# 9. Verifikasi
print("\n===== VERIFIKASI =====")

if plaintext == decrypted_text:
    print("Status: BERHASIL")
    print("Data hasil dekripsi sama dengan plaintext awal.")
else:
    print("Status: GAGAL")
# 10. Pengujian integritas data
print("\n===== PENGUJIAN INTEGRITAS DATA =====")

# Mengubah satu byte pada ciphertext
tampered_data = bytearray(encrypted_data)
tampered_data[0] ^= 1

try:
    # Mencoba dekripsi data yang telah diubah
    aesgcm.decrypt(nonce, bytes(tampered_data), None)

    print("Status: GAGAL")
    print("Perubahan data tidak terdeteksi.")

except InvalidTag:
    print("Status: BERHASIL")
    print("Manipulasi ciphertext berhasil dideteksi.")
    print("Proses dekripsi ditolak karena authentication tag tidak valid.")
