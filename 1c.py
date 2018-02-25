# Generate 10 random keys and 10 messages of different lengths. Encrypt each message under a different
# key with both the library function and your own function. Test that the results match. Test that the
# decryption of the ciphertexts under the same key matches with the original messages.

from Alex_Lobrano_implementation import *

key = [None] * 10
iv = [None] * 10
ctr = [None] * 10
msg = [None] * 10

for i in range(0,10):
	key[i] = os.urandom(16)
	iv[i] = os.urandom(16)
	ctr[i] = os.urandom(16)
	msg[i] = generate_message((i+1)*16)

backend = default_backend()

for i in range(10):
	print "\nNumber of blocks in message:", i+1
	print "Message:", msg[i]
	
	##################### CBC #####################
	cipher = Cipher(algorithms.AES(key[i]), modes.CBC(iv[i]), backend)
	encryptor = cipher.encryptor()
	ciphertext = encryptor.update(msg[i]) + encryptor.finalize()
	my_ciphertext = cbc_encrypt(key[i],iv[i],msg[i])

	print "\nCBC:"
	print "Library encryption: " + ciphertext.encode('hex')
	print "My encryption:      " + my_ciphertext.encode('hex')

	assert ciphertext == my_ciphertext
	
	decryptor = cipher.decryptor()
	plaintext = decryptor.update(ciphertext) + decryptor.finalize()
	my_plaintext = cbc_decrypt(key[i],iv[i],my_ciphertext)
	
	print "Library decryption: " + plaintext
	print "My decryption:      " + my_plaintext

	assert plaintext == my_plaintext
	
	##################### CTR #####################
	cipher = Cipher(algorithms.AES(key[i]), modes.CTR(ctr[i]), backend=default_backend())
	encryptor = cipher.encryptor()
	ciphertext = encryptor.update(msg[i]) + encryptor.finalize()
	my_ciphertext = ctr_encrypt(key[i],ctr[i],msg[i])

	print "\nCTR:"
	print "Library encryption: " + ciphertext.encode('hex')
	print "My encryption:      " + my_ciphertext.encode('hex')

	assert ciphertext == my_ciphertext
	
	decryptor = cipher.decryptor()
	plaintext = decryptor.update(ciphertext) + decryptor.finalize()
	my_plaintext = ctr_decrypt(key[i],ctr[i],my_ciphertext)

	print "Library decryption: " + plaintext
	print "My decryption:      " + my_plaintext
	
	assert plaintext == my_plaintext

	

#assert cipher_text == Cipher_Text_FROM_YOUR_CTR_IMPLEMENTATION