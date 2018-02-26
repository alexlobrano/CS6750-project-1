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
	for i in range(pad_bytes):
		if(plaintext_array[len(plaintext_array)-1-i] != pad_bytes): 
			#print "Invalid padding"
			return 0
	#print "Valid padding"
	return 1

def change_byte(first_byte,pad_byte,value):
	temp = first_byte ^ pad_byte
	return temp ^ value

key = os.urandom(16)
#key = '6dbb3f397f4ef34201e49ecd53b29752'.decode('hex')
iv = os.urandom(16)
#iv = 'e4433307dea03f1668adce1eaf48f501'.decode('hex')
ctr = os.urandom(16)
msg = "This is a test of a padding oracle attack."
#msg = "This is a test of a padding oracle attack. Testing with a second message."
backend = default_backend() 

##################### CBC #####################
print "Message:", msg

cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend)
encryptor = cipher.encryptor()
ciphertext = encryptor.update(msg) + encryptor.finalize()

print "CBC:"
print "Library encryption: " + ciphertext.encode('hex')

# test_cipher_array = bytearray(ciphertext)
# test_cipher_array[0] += 1
# new_ciphertext = ""
# for i in range(len(test_cipher_array)):
	# new_ciphertext += str(chr(test_cipher_array[i]))
# i = 0
# print "New encryption:    ",new_ciphertext.encode('hex')

decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()

print "Library decryption: " + plaintext.encode('hex')

# cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend)
# decryptor = cipher.decryptor()
# new_plaintext = decryptor.update(new_ciphertext) + decryptor.finalize()
# print "New decryption:    ",plaintext.encode('hex')

original_cipher_array = bytearray(ciphertext)
test_cipher_array = bytearray(ciphertext)
test_cipher_array[0] += 1
print "length:",len(test_cipher_array)
print "Changing byte 0 from", format(original_cipher_array[0], 'x'), "to", format(test_cipher_array[0], 'x')
new_ciphertext = ""
for i in range(len(test_cipher_array)):
	new_ciphertext += str(chr(test_cipher_array[i]))
i = 0
while(debug_oracle(key,iv,new_ciphertext)):
	new_ciphertext = ""
	i += 1 
	test_cipher_array[i-1] = original_cipher_array[i-1]
	test_cipher_array[i] += 1
	print "Changing byte", i, "from", format(original_cipher_array[i], 'x'), "to", format(test_cipher_array[i], 'x')
	for j in range(len(test_cipher_array)):
		new_ciphertext += str(chr(test_cipher_array[j]))
padding_bytes = (len(test_cipher_array)-i)%16
last_byte = i
print "Bytes of padding:",padding_bytes
print "Last byte of last block:",last_byte
test_cipher_array = bytearray(ciphertext)
recovered_msg = [None] * (16-padding_bytes)
for x in range(0, 16-padding_bytes):
	for k in range(last_byte-x, last_byte+padding_bytes):
		test_cipher_array[k] = change_byte(test_cipher_array[k],padding_bytes+x,padding_bytes+x+1)
		print "Changing byte", k, "from", format(original_cipher_array[k], 'x'), "to", format(test_cipher_array[k], 'x')
	new_ciphertext = ""
	for i in range(len(test_cipher_array)):
		new_ciphertext += str(chr(test_cipher_array[i]))
	m = 0
	while(not debug_oracle(key,iv,new_ciphertext)):
		m += 1
		temp = test_cipher_array[last_byte-x-1] + 1		# save value to temp before saving to bytearray to avoid out of range problems
		temp = temp % 256
		test_cipher_array[last_byte-x-1] = temp
		#print "Byte is now",test_cipher_array[last_byte-x-1]
		new_ciphertext = ""
		for i in range(len(test_cipher_array)):
			new_ciphertext += str(chr(test_cipher_array[i]))
	print "M:", m
	temp = test_cipher_array[last_byte-x-1] ^ (padding_bytes+x+1)
	plain_byte = temp ^ original_cipher_array[last_byte-x-1]
	print "Xor value:", padding_bytes+x+1
	#plain_byte = m ^ (padding_bytes+x+1)
	print "Plaintext byte:", plain_byte
	recovered_msg[x] = plain_byte
recovered_text = ""
for i in range(len(recovered_msg)):
	recovered_text += str(chr(recovered_msg[len(recovered_msg)-i-1]))
print "Recovered message:", recovered_text
		
#if(padding_oracle(key,iv,my_ciphertext)): print "Valid padding"
#else: print "Invalid padding"

#bin(int(plaintext.encode('hex'),16))

#6c652061747461636b2e