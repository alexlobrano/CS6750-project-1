# 1a.py

# Use the functions provided by the library to encrypt a message m under key k (uniformly chosen)
# using AES encryption in CBC and CTR modes. Implement decryption of a ciphertext c under key k
# in CBC and CTR modes using the library functions.

from Alex_Lobrano_implementation import *

key = os.urandom(16)
iv = os.urandom(16)
ctr = os.urandom(16)
msg = generate_message(16)
backend = default_backend()

##################### CBC #####################
print "Message:", msg

cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend)
encryptor = cipher.encryptor()
ciphertext = encryptor.update(msg) + encryptor.finalize()

print "\nCBC:"
print "Library encryption: " + ciphertext.encode('hex')

decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()

print "Library decryption: " + plaintext

##################### CTR #####################
cipher = Cipher(algorithms.AES(key), modes.CTR(ctr), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(msg) + encryptor.finalize()

print "\nCTR:"
print "Library encryption: " + ciphertext.encode('hex')

decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()

print "Library decryption: " + plaintext