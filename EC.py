# EC.py

# Extend the attack to recover the entire message. Print the total number of queries
# to the padding oracle, as well as all the queries you need to do per block and the answers from the padding
# oracle.

from Alex_Lobrano_implementation import *
	
key = os.urandom(16)
iv = os.urandom(16)
ctr = os.urandom(16)
msg = "This is a test of a padding oracle attack."
#msg = "This is a test of a padding oracle attack. Testing with a longer message."
#msg = "Test two blocks perfect padding."
#msg = "Perfect padding."
#msg = "Test message."
backend = default_backend() 

##################### CBC #####################

print "Message:", msg

cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend)
encryptor = cipher.encryptor()
ciphertext = encryptor.update(msg) + encryptor.finalize()

print "CBC:"
print "Library encryption: " + ciphertext.encode('hex')

decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()

print "Library decryption: " + plaintext.encode('hex')

oracle_attack_full_recovery(key, iv, ciphertext)
