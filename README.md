from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_key_pair(public_key_value=47, private_key_value=4763):
    key = RSA.generate(2048, e=public_key_value)
    
    e = key.e
    
    d = pow(e, -1, (key.p - 1) * (key.q - 1))
    
    key = RSA.construct((key.n, e, d, key.p, key.q))

    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def save_key_to_file(key, filename):
    with open(filename, 'wb') as f:
        f.write(key)

def load_key_from_file(filename):
    with open(filename, 'rb') as f:
        key = f.read()
    return key

def encrypt_message(message, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(message.encode())
    return ciphertext

def decrypt_message(ciphertext, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    decrypted_message = cipher.decrypt(ciphertext).decode()
    return decrypted_message

private_key, public_key = generate_key_pair(public_key_value=47, private_key_value=4763)

print("Private Key:")
print(private_key.decode())
print("\nPublic Key:")
print(public_key.decode())

save_key_to_file(private_key, 'private_key.pem')
save_key_to_file(public_key, 'public_key.pem')

loaded_private_key = load_key_from_file('private_key.pem')
loaded_public_key = load_key_from_file('public_key.pem')

pesan = "INDAH_171080200284_UAS_PABW!"
print(f"\nPesan asli: {pesan}")

ciphertext = encrypt_message(pesan, loaded_public_key)
print(f"Pesan terenkripsi: {ciphertext}")

decrypted_message = decrypt_message(ciphertext, loaded_private_key)
print(f"Pesan terdekripsi: {decrypted_message}")
