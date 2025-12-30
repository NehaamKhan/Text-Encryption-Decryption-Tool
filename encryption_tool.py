from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# --- HELPER: Auto-detect End of Key ---
def get_rsa_key_input():
    print("\n[INSTRUCTION] Paste the Private Key below.")
    print("(Include the '-----BEGIN RSA PRIVATE KEY-----''-----END RSA PRIVATE KEY-----' line)")
    print("-" * 50)
    
    lines = []
    while True:
        try:
            line = input()
            lines.append(line)
            # Stop automatically if we see the footer line
            if "-----END RSA PRIVATE KEY-----" in line:
                break
        except EOFError:
            break
            
    return "\n".join(lines)

# --- ENCRYPTION LOGIC ---
def encrypt_aes(text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(text.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')

def encrypt_des(text, key):
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(text.encode(), DES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')

def encrypt_rsa(text, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(text.encode())
    return base64.b64encode(ciphertext).decode('utf-8')

# --- DECRYPTION LOGIC ---
def decrypt_aes(ciphertext, key_hex):
    try:
        key = bytes.fromhex(key_hex) 
        raw = base64.b64decode(ciphertext)
        iv = raw[:16]
        ct = raw[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
    except Exception as e:
        return f"Error: {e}"

def decrypt_des(ciphertext, key_hex):
    try:
        key = bytes.fromhex(key_hex) 
        raw = base64.b64decode(ciphertext)
        iv = raw[:8]
        ct = raw[8:]
        cipher = DES.new(key, DES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), DES.block_size).decode('utf-8')
    except Exception as e:
        return f"Error: {e}"

def decrypt_rsa(ciphertext, private_key_str):
    try:
        private_key = RSA.import_key(private_key_str)
        raw = base64.b64decode(ciphertext)
        cipher = PKCS1_OAEP.new(private_key)
        return cipher.decrypt(raw).decode('utf-8')
    except ValueError:
        return "Error: RSA key format is incorrect. Did you copy the headers?"
    except Exception as e:
        return f"Error: {e}"

# --- MAIN MENU ---
def main():
    print("--- Text Encryption Tool ---")
    
    # Generate session keys
    session_aes = get_random_bytes(16)
    session_des = get_random_bytes(8)
    session_rsa = RSA.generate(2048)

    while True:
        print("\n" + "="*50)
        print("1. Encrypt Text (Generates & Shows Key)")
        print("2. Decrypt Text (Manual Key Input)")
        print("3. Exit")
        print("="*50)
        
        choice = input("Select Option: ")

        if choice == '3': break
        
        # --- ENCRYPTION MODE ---
        if choice == '1': 
            print("\nSelect Algorithm:")
            print("A. AES")
            print("B. DES")
            print("C. RSA")
            algo = input("Choice: ").upper()
            text = input("Enter text to encrypt: ")

            if algo == 'A':
                res = encrypt_aes(text, session_aes)
                print(f"\n[SUCCESS] Encrypted String:\n{res}")
                print(f"\n[IMPORTANT] KEY (Copy this!):\n{session_aes.hex()}")

            elif algo == 'B':
                res = encrypt_des(text, session_des)
                print(f"\n[SUCCESS] Encrypted String:\n{res}")
                print(f"\n[IMPORTANT] KEY (Copy this!):\n{session_des.hex()}")

            elif algo == 'C':
                pub_key = session_rsa.publickey()
                res = encrypt_rsa(text, pub_key)
                print(f"\n[SUCCESS] Encrypted String:\n{res}")
                print(f"\n[IMPORTANT] PRIVATE KEY (Copy ALL lines below!):")
                print("-" * 20 + " START COPY " + "-" * 20)
                print(session_rsa.export_key().decode())
                print("-" * 20 + " END COPY " + "-" * 20)

        # --- DECRYPTION MODE ---
        elif choice == '2': 
            print("\nSelect Algorithm:")
            print("A. AES")
            print("B. DES")
            print("C. RSA")
            algo = input("Choice: ").upper()
            cipher = input("Enter Ciphertext (Base64): ")

            if algo == 'A':
                key_input = input("Enter AES Key (Hex): ")
                print(f"Decrypted: {decrypt_aes(cipher, key_input)}")
            
            elif algo == 'B':
                key_input = input("Enter DES Key (Hex): ")
                print(f"Decrypted: {decrypt_des(cipher, key_input)}")
            
            elif algo == 'C':
                key_input = get_rsa_key_input()
                print(f"Decrypted: {decrypt_rsa(cipher, key_input)}")

if __name__ == "__main__":
    main()
