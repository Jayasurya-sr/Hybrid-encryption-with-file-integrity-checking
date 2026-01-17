# Hybrid-encryption-with-file-integrity-checking
This project secures files using AES for encryption, RSA for key protection, and SHA-256 for integrity checking, ensuring data confidentiality and tamper detection.

Hybrid Encryption System with File Integrity Checking

Project Description
This project implements a Hybrid Encryption System using Python. It combines AES for fast file encryption, RSA for secure key exchange, and SHA-256 for file integrity checking to ensure data confidentiality and tamper detection.

Technologies Used
Python 3
AES (Advanced Encryption Standard)
RSA (Public Key Cryptography)
SHA-256 (Integrity Hashing)
cryptography Python library

Features
Encrypts files using AES symmetric encryption
Secures AES key using RSA asymmetric encryption
Verifies file integrity using SHA-256 hash
Detects unauthorized file modification
Supports any file type

Project Structure
DesignProject.py
sample.txt
sample.txt.enc
decrypted_output
README.txt

How to Run the Project

Install the required library using:
pip install cryptography

Run the program using:
python DesignProject.py

Enter the file name when prompted:
sample.txt

Output Files
sample.txt.enc – Encrypted file
decrypted_output – Decrypted original file

Working Explanation
The file is encrypted using AES.
The AES key is encrypted using RSA.
A SHA-256 hash is generated to ensure file integrity.
During decryption, the hash is verified to detect tampering before decrypting the file.

Use Cases
Secure file storage
Secure file transfer
Academic cryptography projects
Learning hybrid encryption concepts

Author
Jayasurya S.R

License
This project is created for educational purposes only.
