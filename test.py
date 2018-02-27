from Alex_Lobrano_implementation import *

def debug_cbc_decrypt(key, iv, msg):
	cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
	decryptor = cipher.decryptor()
	
	total_bytes = (len(msg)/16)
	plaintext_array = [None] * total_bytes
	
	#byte 1
	plaintext_array[0] = xor(decryptor.update(msg[0:16]),iv)
	plaintext = plaintext_array[0]
	
	#rest of bytes
	for i in range(1,total_bytes):
		xor_val = decryptor.update(msg[(i)*16:(i+1)*16])
		#print "Xor F_k value",xor_val.encode('hex'),"and",msg[(i-1)*16:i*16].encode('hex'),"for byte",i
		plaintext_array[i] = xor(xor_val,msg[(i-1)*16:i*16])
		plaintext += plaintext_array[i]
	return plaintext

def debug_oracle(key,iv,ciphertext):
	#print "Ciphertext:",ciphertext.encode('hex')
	plaintext = debug_cbc_decrypt(key, iv, ciphertext)
	#print "Decryption:",plaintext.encode('hex')
	plaintext_array = bytearray(plaintext)
	#for i in range(len(plaintext_array)):
	#	print "i:",i,plaintext_array[i]
	pad_bytes = plaintext_array[len(plaintext_array)-1]
	#print "Expected bytes:", pad_bytes
	if(pad_bytes == 0): return 0	#if last byte is 0, invalid pad
	for i in range(pad_bytes):
		if(plaintext_array[len(plaintext_array)-1-i] != pad_bytes): 
			#print "Invalid padding"
			return 0
	#print "Valid padding"
	return 1	
	
#key = os.urandom(16)
key = '6dbb3f397f4ef34201e49ecd53b29752'.decode('hex')
#iv = os.urandom(16)
iv = 'e4433307dea03f1668adce1eaf48f501'.decode('hex')
ctr = os.urandom(16)
msg = "This is a test of a padding oracle attack."
#msg = "This is a test of a padding oracle attack. Testing with a second message."
#msg = "This is a test of a padding oracle attack. Testing with a second"
backend = default_backend() 

##################### CBC #####################
print "Message:", msg

cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend)
encryptor = cipher.encryptor()
ciphertext = encryptor.update(msg) + encryptor.finalize()
#ciphertext = cbc_encrypt(key,iv,msg)

print "CBC:"
print "Library encryption: " + ciphertext.encode('hex')

#decryptor = cipher.decryptor()
#plaintext = decryptor.update(ciphertext) + decryptor.finalize()
plaintext = debug_cbc_decrypt(key,iv,ciphertext)

print "Library decryption: " + plaintext.encode('hex')

#attack starts here

original_cipher_array = bytearray(ciphertext)
original_iv_array = bytearray(iv)
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
	#print "Changing byte", i, "from", format(original_cipher_array[i], 'x'), "to", format(test_cipher_array[i], 'x')
	new_ciphertext = create_string(test_cipher_array)
	
padding_bytes = (len(test_cipher_array)-i)%16
first_pad_byte = i
print "Bytes of padding:",padding_bytes
print "Byte to use to modify first byte of padding:",first_pad_byte
test_cipher_array = bytearray(ciphertext)
recovered_msg = [None] * (len(ciphertext)-padding_bytes)
for x in range(0, 16-padding_bytes):
	#update the value of bytes determined to be padding to 1 higher than the number of pad bytes
	for k in range(first_pad_byte-x, first_pad_byte+padding_bytes):
		test_cipher_array[k] = change_byte(test_cipher_array[k],padding_bytes+x,padding_bytes+x+1)
		#print "Changing byte", k, "from", format(original_cipher_array[k], 'x'), "to", format(test_cipher_array[k], 'x')
	new_ciphertext = create_string(test_cipher_array)
	
	#loop and increment the value of the last byte before the pad bytes until there is valid padding
	m = 0
	while(not debug_oracle(key,iv,new_ciphertext)):
		m += 1
		test_cipher_array[first_pad_byte-x-1] = increment_byte(test_cipher_array[first_pad_byte-x-1])
		new_ciphertext = create_string(test_cipher_array)
	#print "M:", m
	temp = test_cipher_array[first_pad_byte-x-1] ^ (padding_bytes+x+1)
	plain_byte = temp ^ original_cipher_array[first_pad_byte-x-1]
	#print "Xor value:", padding_bytes+x+1
	#print "Plaintext byte:", chr(plain_byte)
	recovered_msg[len(ciphertext)-padding_bytes-x-1] = plain_byte
	print "Saving",chr(plain_byte),"to index",len(ciphertext)-padding_bytes-x-1
	
#make new ciphertext without last byte
new_length = len(test_cipher_array) - 16	#64
while(new_length > 16):
	test_cipher_array = bytearray(ciphertext[:new_length])	#:64
	new_ciphertext = create_string(test_cipher_array)
	print "Reduced cipher:", new_ciphertext.encode('hex')

	# #make last byte equal 1
	first_pad_byte = new_length - 16 - 1 #48
	m = 0
	while(not debug_oracle(key,iv,new_ciphertext)):
		m += 1
		test_cipher_array[first_pad_byte] = increment_byte(test_cipher_array[first_pad_byte])
		new_ciphertext = create_string(test_cipher_array)
		
	padding_bytes = 1
	#print "M:", m
	temp = test_cipher_array[first_pad_byte] ^ padding_bytes
	plain_byte = temp ^ original_cipher_array[first_pad_byte]
	#print "Xor value:", padding_bytes
	#print "Plaintext byte:", chr(plain_byte)
	recovered_msg[new_length-1] = plain_byte
	print "Saving",chr(plain_byte),"to index",new_length-1

	for x in range(0, 15):
		#update the value of bytes determined to be padding to 1 higher than the number of pad bytes
		for k in range(first_pad_byte-x, first_pad_byte+padding_bytes):
			test_cipher_array[k] = change_byte(test_cipher_array[k],padding_bytes+x,padding_bytes+x+1)
			#print "Changing byte", k, "from", format(original_cipher_array[k], 'x'), "to", format(test_cipher_array[k], 'x')
		new_ciphertext = create_string(test_cipher_array)
		
		#loop and increment the value of the last byte before the pad bytes until there is valid padding
		m = 0
		while(not debug_oracle(key,iv,new_ciphertext)):
			m += 1
			test_cipher_array[first_pad_byte-x-1] = increment_byte(test_cipher_array[first_pad_byte-x-1])
			new_ciphertext = create_string(test_cipher_array)
		#print "M:", m
		temp = test_cipher_array[first_pad_byte-x-1] ^ (padding_bytes+x+1)
		plain_byte = temp ^ original_cipher_array[first_pad_byte-x-1]
		#print "Xor value:", padding_bytes+x+1
		#print "Plaintext byte:", chr(plain_byte)
		recovered_msg[new_length-x-2] = plain_byte
		print "Saving",chr(plain_byte),"to index",new_length-x-2
	new_length = len(test_cipher_array) - 16	#64
		
#recover first byte (new_length is now equal to 16)
test_cipher_array = bytearray(ciphertext[:new_length])	#:16
new_ciphertext = create_string(test_cipher_array)
test_iv_array = bytearray(iv)
new_iv = create_string(test_iv_array)
print "Reduced cipher:", new_ciphertext.encode('hex')

# #make last byte equal 1
first_pad_byte = new_length - 1 #15
print "First pad byte:", first_pad_byte
m = 0
while(not debug_oracle(key,new_iv,new_ciphertext)):
	m += 1
	test_iv_array[first_pad_byte] = increment_byte(test_iv_array[first_pad_byte])
	new_iv = create_string(test_iv_array)
padding_bytes = 1
#print "M:", m
temp = test_iv_array[first_pad_byte] ^ padding_bytes
plain_byte = temp ^ original_iv_array[first_pad_byte]
#print "Xor value:", padding_bytes
#print "Plaintext byte:", chr(plain_byte)
recovered_msg[new_length-1] = plain_byte
print "Saving",chr(plain_byte),"to index",new_length-1

for x in range(0, 15):
	#update the value of bytes determined to be padding to 1 higher than the number of pad bytes
	for k in range(first_pad_byte-x, first_pad_byte+padding_bytes):
		test_iv_array[k] = change_byte(test_iv_array[k],padding_bytes+x,padding_bytes+x+1)
		#print "Changing byte", k, "of IV from", format(original_iv_array[k], 'x'), "to", format(test_iv_array[k], 'x')
	new_iv = create_string(test_iv_array)
	
	#loop and increment the value of the last byte before the pad bytes until there is valid padding
	m = 0
	while(not debug_oracle(key,new_iv,new_ciphertext)):
		m += 1
		test_iv_array[first_pad_byte-x-1] = increment_byte(test_iv_array[first_pad_byte-x-1])
		new_iv = create_string(test_iv_array)
	#print "M:", m
	temp = test_iv_array[first_pad_byte-x-1] ^ (padding_bytes+x+1)
	plain_byte = temp ^ original_iv_array[first_pad_byte-x-1]
	#print "Xor value:", padding_bytes+x+1
	#print "Plaintext byte:", chr(plain_byte)
	recovered_msg[new_length-x-2] = plain_byte
	print "Saving",chr(plain_byte),"to index",new_length-x-2
		
	
recovered_text = ""
for i in range(len(recovered_msg)):
	recovered_text += str(chr(recovered_msg[i]))
print "Recovered message:", recovered_text
