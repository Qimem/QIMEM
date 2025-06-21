import qimem
import os
import pytest

def test_encrypt_decrypt():
    try:
        key, _ = qimem.py_derive_key("password", None)
        data = b"Sensitive data"
        encrypted = qimem.py_encrypt(data, key)
        print(f"Encrypted type: {type(encrypted)}, value: {encrypted}")
        decrypted = qimem.py_decrypt(encrypted, key)
        print(f"Decrypted type: {type(decrypted)}, value: {decrypted}")
        assert isinstance(decrypted, bytes), f"Expected bytes, got {type(decrypted)}"
        assert decrypted == data, f"Expected {data}, got {decrypted}"
    except Exception as e:
        pytest.fail(f"Test failed with exception: {str(e)}")

def test_file_encryption():
    try:
        key, salt = qimem.py_derive_key("password", None)
        with open("test.txt", "wb") as f:
            f.write(b"Secret file")
        qimem.py_encrypt_file("test.txt", "test.enc", key, salt)
        qimem.py_decrypt_file("test.enc", "test.dec", key)
        with open("test.dec", "rb") as f:
            content = f.read()
            assert content == b"Secret file", f"Expected b'Secret file', got {content}"
    except Exception as e:
        pytest.fail(f"Test failed with exception: {str(e)}")
    finally:
        for file in ["test.txt", "test.enc", "test.dec"]:
            if os.path.exists(file):
                os.remove(file)

def test_sign_verify():
    try:
        public_key, secret_key = qimem.py_generate_keypair()
        message = b"Test message"
        signature = qimem.py_sign_message(secret_key, message)
        assert qimem.py_verify_signature(public_key, message, signature), "Signature verification failed"
    except Exception as e:
        pytest.fail(f"Test failed with exception: {str(e)}")