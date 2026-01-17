import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ---------------- RSA KEY GENERATION ----------------
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

# ---------------- AES KEY GENERATION ----------------
def generate_aes_key():
    aes_key = os.urandom(32)   # 256-bit AES key
    iv = os.urandom(16)        # 128-bit IV
    return aes_key, iv

# ---------------- AES ENCRYPTION ----------------
def encrypt_data_aes(data, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

# ---------------- AES DECRYPTION ----------------
def decrypt_data_aes(encrypted_data, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

# ---------------- RSA ENCRYPT AES KEY ----------------
def encrypt_aes_key_rsa(aes_key, public_key):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# ---------------- RSA DECRYPT AES KEY ----------------
def decrypt_aes_key_rsa(encrypted_aes_key, private_key):
    return private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# ---------------- HASH FOR INTEGRITY ----------------
def generate_hash(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

# ---------------- ENCRYPT FILE ----------------
def encrypt_file_with_integrity(filepath, public_key):
    with open(filepath, 'rb') as f:
        plaintext = f.read()

    aes_key, iv = generate_aes_key()
    encrypted_data = encrypt_data_aes(plaintext, aes_key, iv)
    encrypted_aes_key = encrypt_aes_key_rsa(aes_key, public_key)
    integrity_hash = generate_hash(encrypted_data)

    with open(filepath + ".enc", "wb") as f:
        f.write(encrypted_aes_key)  # 256 bytes
        f.write(iv)                 # 16 bytes
        f.write(encrypted_data)
        f.write(integrity_hash)     # 32 bytes

    print("✅ File encrypted successfully with integrity check.")

# ---------------- DECRYPT FILE ----------------
def decrypt_file_with_integrity(filepath, private_key):
    with open(filepath, 'rb') as f:
        file_data = f.read()

    encrypted_aes_key = file_data[:256]
    iv = file_data[256:272]
    encrypted_data = file_data[272:-32]
    stored_hash = file_data[-32:]

    # Integrity check
    calculated_hash = generate_hash(encrypted_data)
    if calculated_hash != stored_hash:
        print("❌ Integrity check failed! File may be tampered.")
        return

    aes_key = decrypt_aes_key_rsa(encrypted_aes_key, private_key)
    decrypted_data = decrypt_data_aes(encrypted_data, aes_key, iv)

    with open("decrypted_output", "wb") as f:
        f.write(decrypted_data)

    print("✅ Integrity verified. File decrypted successfully.")

# ---------------- MAIN ----------------
if __name__ == "__main__":
    private_key, public_key = generate_rsa_keys()

    filepath = input("Enter file path to encrypt: ")

    encrypt_file_with_integrity(filepath, public_key)
    decrypt_file_with_integrity(filepath + ".enc", private_key)
