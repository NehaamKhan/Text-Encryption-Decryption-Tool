# Text Encryption Tool (AES • DES • RSA)

This is a simple text encryption and decryption tool implemented in Python. It allows users to securely encrypt and decrypt text using AES, DES, and RSA algorithms. The tool provides an interactive command-line interface and supports both symmetric and asymmetric cryptography.

## 📸 Screenshot

<img width="1918" height="1020" alt="image" src="https://github.com/user-attachments/assets/3a8114d5-0241-4091-b7a0-ee211590beae" />
<img width="1918" height="1018" alt="image" src="https://github.com/user-attachments/assets/c2726d8e-9a70-44ab-8fa9-f99707f40f44" />


## Features

- **Multiple Algorithms**: Supports AES, DES, and RSA encryption and decryption.
- **Session-Based Key Generation**:
  - Automatically generates AES and DES session keys.
  - Generates a 2048-bit RSA key pair per session.
- **Manual Key Decryption**:
  - AES & DES require manual hexadecimal key input.
  - RSA requires the full private key including headers.
- **Base64 Encoding**: Encrypted output is Base64-encoded for safe storage and transfer.
- **Auto RSA Key Detection**: Automatically detects the end of RSA private key input.
- **Menu-Driven CLI**: Simple and interactive command-line interface.

## Prerequisites

- Python 3.x
- `pycryptodome` library

## Installation

### Step 1: Install Required Libraries

```bash
pip install pycryptodome
```

### Step 2: Download or Clone the Repository

```bash
git clone https://github.com/NehaamKhan/Text-Encryption-Decryption-Tool.git
```

### Step 3: Navigate to the Project Directory

```bash
cd text-encryption-tool
```

## Usage

### Step 1: Run the Script

```bash
python encryption_tool.py
```

### Step 2: Choose an Option

```
1. Encrypt Text (Generates & Shows Key)
2. Decrypt Text (Manual Key Input)
3. Exit
```

### Step 3: Encryption Mode

- Select the encryption algorithm (AES / DES / RSA)
- Enter the plaintext
- The program will display:
  - Encrypted Base64 ciphertext
  - Required decryption key

### Step 4: Decryption Mode

- Select the algorithm used for encryption
- Paste the Base64 ciphertext
- Provide the corresponding key:
  - **AES / DES** → Hexadecimal key
  - **RSA** → Full private key

```
-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----
```

### Step 5: Exit

Select option `3` to safely exit the program.

## Notes

- AES uses CBC mode with PKCS7 padding.
- DES uses CBC mode with PKCS7 padding.
- RSA uses OAEP padding (PKCS1_OAEP).
- Store encryption keys securely; losing them will make decryption impossible.
- This project is intended for educational purposes only.

## License

This project is licensed under the [MIT License](License).
