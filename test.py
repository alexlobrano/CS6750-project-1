from Alex_Lobrano_implementation import *

def debug_oracle(key,iv,ciphertext):
	#print "Ciphertext:",ciphertext.encode('hex')
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend)
	decryptor = cipher.decryptor()
	plaintext = decryptor.update(ciphertext) + decryptor.finalize()
	#print "Decryption:",plaintext.encode('hex')
	plaintext_array = bytearray(plaintext)
	#for i in range(len(plaintext_array)):
	#	print "i:",i,plaintext_array[i]
	pad_bytes = plaintext_array[len(plaintext_array)-1]
	if(pad_bytes == 0): return 0	#if last byte is 0, invalid pad
	for i in range(pad_bytes):
		if(plaintext_array[len(plaintext_array)-1-i] != pad_bytes): 
			#print "Invalid padding"
			return 0
	#print "Valid padding"
	return 1

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

#attack starts here

original_cipher_array = bytearray(ciphertext)
test_cipher_array = bytearray(ciphertext)
test_cipher_array[0] = increment_byte(test_cipher_array[0])
print "length:",len(test_cipher_array)
print "Changing byte 0 from", format(original_cipher_array[0], 'x'), "to", format(test_cipher_array[0], 'x')
new_ciphertext = create_string(test_cipher_array)
i = 0

while(padding_oracle(key,iv,new_ciphertext)):
	i += 1 
	test_cipher_array[i-1] = original_cipher_array[i-1]
	test_cipher_array[i] = increment_byte(test_cipher_array[i])
	print "Changing byte", i, "from", format(original_cipher_array[i], 'x'), "to", format(test_cipher_array[i], 'x')
	new_ciphertext = create_string(test_cipher_array)
	
padding_bytes = (len(test_cipher_array)-i)%16
first_pad_byte = i
print "Bytes of padding:",padding_bytes
print "First byte to invalidate padding:",first_pad_byte
test_cipher_array = bytearray(ciphertext)
recovered_msg = [None] * (16-padding_bytes)
for x in range(0, 16-padding_bytes):
	#update the value of bytes determined to be padding to 1 higher than the number of pad bytes
	for k in range(first_pad_byte-x, first_pad_byte+padding_bytes):
		test_cipher_array[k] = change_byte(test_cipher_array[k],padding_bytes+x,padding_bytes+x+1)
		print "Changing byte", k, "from", format(original_cipher_array[k], 'x'), "to", format(test_cipher_array[k], 'x')
	new_ciphertext = create_string(test_cipher_array)
	
	#loop and increment the value of the last byte before the pad bytes until there is valid padding
	m = 0
	while(not padding_oracle(key,iv,new_ciphertext)):
		m += 1
		test_cipher_array[first_pad_byte-x-1] = increment_byte(test_cipher_array[first_pad_byte-x-1])
		new_ciphertext = create_string(test_cipher_array)
	print "M:", m
	temp = test_cipher_array[first_pad_byte-x-1] ^ (padding_bytes+x+1)
	plain_byte = temp ^ original_cipher_array[first_pad_byte-x-1]
	print "Xor value:", padding_bytes+x+1
	print "Plaintext byte:", plain_byte
	recovered_msg[x] = plain_byte
	
recovered_text = ""
for i in range(len(recovered_msg)):
	recovered_text += str(chr(recovered_msg[len(recovered_msg)-i-1]))
print "Recovered message:", recovered_text