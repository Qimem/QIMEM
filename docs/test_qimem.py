import qimem
data = "አበበ፣ ምርት: 500ኪግ በቆሎ".encode('utf-8')
password = "farmer_pass"
salt = "AxumObelisk2025አክሱም"
key = qimem.derive_key(password, salt)
ciphertext = qimem.encrypt(data, key)
print(f"Ciphertext (base64): {ciphertext.hex()}")
decrypted = qimem.decrypt(ciphertext, key)
print(f"Decrypted: {decrypted.decode('utf-8')}")
