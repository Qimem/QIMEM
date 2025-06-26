import qimem
import pytest
import base64
import time
import os

def test_key_derivation():
    key, salt = qimem.derive_key("password", None)
    assert len(key) == 32
    assert len(salt) == 16
    key2, salt2 = qimem.derive_key("password", "mysalt2025")
    assert len(key2) == 32
    assert len(salt2) == 16
    assert key != key2

def test_salt_rotation():
    key1, salt1 = qimem.derive_key_with_rotation("password", "mysalt2025", 30)
    key2, salt2 = qimem.derive_key_with_rotation("password", "mysalt2025", 30)
    assert salt1 == salt2
    assert key1 == key2

def test_key_store():
    try:
        os.remove("/tmp/qimem_keys")
    except FileNotFoundError:
        pass
    keystore = qimem.KeyStore("/tmp/qimem_keys", "masterpass")
    key = b"\x01" * 32
    keystore.store_key("test", key)
    retrieved = keystore.retrieve_key("test_20250622T2115Z")
    assert retrieved == key
    keystore.email_key("test_20250622T2115Z", "test@example.com")

def test_encrypt_decrypt():
    key, _ = qimem.derive_key("password", None)
    data = b"secret data"
    encrypted = qimem.encrypt(data, key)
    decrypted = qimem.decrypt(encrypted, key)
    assert decrypted == data

def test_file_encryption():
    key, salt = qimem.derive_key("password", None)
    with open("/tmp/test.txt", "wb") as f:
        f.write(b"secret data")
    qimem.encrypt_file("/tmp/test.txt", "/tmp/test.enc", key, salt)
    qimem.decrypt_file("/tmp/test.enc", "/tmp/test.dec", key)
    with open("/tmp/test.dec", "rb") as f:
        assert f.read() == b"secret data"

def test_signing():
    public_key, secret_key = qimem.generate_keypair()
    message = b"test"
    signature = qimem.sign_message(secret_key, message)
    assert qimem.verify_signature(public_key, message, signature)

def test_token():
    public_key, _ = qimem.generate_keypair()
    token = qimem.issue_token("alice", "admin", 24)
    assert qimem.verify_token(token, public_key)

def test_totp():
    secret = qimem.generate_totp_secret()
    code = qimem.get_totp_code(secret)
    assert qimem.verify_totp_code(secret, code)

def test_obfuscation():
    qimem.generate_whitepaper_outline()
    assert open("qss_whitepaper_outline.txt").read()
    assert not qimem.anti_debug_check()

def test_bucketing():
    try:
        os.remove("/tmp/bucket.txt")
    except FileNotFoundError:
        pass
    qimem.bucket_sensitive_data("SSN: 123-45-6789", "/tmp/bucket.txt")
    with open("/tmp/bucket.txt") as f:
        assert "123-45-6789" in f.read()