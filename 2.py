# Implement the padding oracle attack discussed in class and presented in chapter 3.7.2 of the
# [Katz-Lindell] textbook. You can query the padding oracle with any ciphertext except c.
# For a particular message m and ciphertext c, print all steps of the attack including the exact queries and
# answers from the padding oracle. Output the last block of the plaintext and the total number of queries to
# the padding oracle needed for the attack to be successful.

from Alex_Lobrano_implementation import *
	
key = os.urandom(16)
iv = os.urandom(16)
ctr = os.urandom(16)
#msg = "This is a test of a padding oracle attack."
msg = "This is a test of a padding oracle attack. Testing with a second message."
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

oracle_attack_last_block_recovery(key, iv, ciphertext)
