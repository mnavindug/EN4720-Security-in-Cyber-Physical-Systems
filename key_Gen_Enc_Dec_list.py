import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as paddingAs
from cryptography.hazmat.primitives import padding
from Crypto.Cipher import DES
from flask import Flask, request, jsonify
import base64

key_dictionary = []
def generateKey(algo, keySize):
    if key_dictionary == []:
        key_id = -1
    else:
        key_id = key_dictionary[-1]['id']
    
    if algo == 'AES' or 'DES' or '3DES':
        key = os.urandom(int(keySize/8))
        key_id = key_id+1

        key_dictionary.append({'id':key_id,
                           "algorithm":algo,
                           "private_key":key, 
                           "public_key":""}  )
        return key
    
    if algo == 'RSA':
        
        private_key = rsa.generate_private_key(
            public_exponent=65537, #a prime number such as being relatively prime to 𝜙(𝑛)=(p-1)x(q-1) ,p,q prime of n 
            key_size=int(int(keySize/8)),
        )
        public_key = private_key.public_key()
        key_dictionary.append({'id':key_id+1,"algorithm":algo,"private_key":private_key, "public_key":public_key}  )
        return private_key
    
def encryption(algo, key_id, data):
    data = data.encode('utf-8')
    key = key_dictionary[key_id]['private_key']
    ksize = len(key)
    
    if algo == 'AES':
        # Generate a random Initialization Vector (IV)
        iv = os.urandom(int(128/8))  # IV should be unique for each encryption 16 bit fixed size (AES blocksize is 128 bits)
        

        # Padding data to fit block size (16 bytes for AES)
        padder = padding.PKCS7(ksize*8).padder()  # Block size is 128 bits = 16 bytes
        padded_data = padder.update(data) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        key_dictionary[key_id]['cipher'] = cipher
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return ct
    
    if algo == 'DES':
        # Generate a random Initialization Vector (IV)
        iv = os.urandom(int(64/8))  # IV should be unique for each encryption 16 bit fixed size (DES blocksize is 64 bits)

        # Create DES cipher in CBC mode
        cipher = DES.new(key, DES.MODE_CBC, iv)
        key_dictionary[key_id]['cipher'] = cipher
        padded_plaintext = data.ljust(16, b'\x00')  # Pad to 16 bytes
        ct = cipher.encrypt(padded_plaintext)

        return ct
    
    if algo == '3DES':
        iv = os.urandom(int(64/8))  # IV should be unique for each encryption 16 bit fixed size (DES blocksize is 64 bits)
        key_dictionary[key_id]['iv'] = iv
    
        # Padding data to fit block size (16 bytes for AES)
        padder = padding.PKCS7(ksize*8).padder()  # Block size is 128 bits = 16 bytes
        padded_data = padder.update(data) + padder.finalize()

        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
        key_dictionary[key_id]['cipher'] = cipher
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return ct
    
    if algo == 'RSA':
        public_key = key_dictionary[key_id]['public_key']
        key_dictionary[key_id]['cipher'] = ""
        ct = public_key.encrypt(
            data,
            paddingAs.OAEP(
                mgf=paddingAs.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ct

def decryption(algo, key_id, cipher_text):
    key = key_dictionary[key_id]['private_key']

    if algo == 'AES':
        cipher = key_dictionary[key_id]['cipher']
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(cipher_text) + decryptor.finalize()
        # Remove padding
        unpadder = padding.PKCS7(len(key)*8).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        return decrypted_data
    
    if algo == 'DES':
        iv = key_dictionary[key_id]['iv']
        decipher = key_dictionary[key_id]['cipher']
        decrypted_padded_plaintext = decipher.decrypt(cipher_text)
        decrypted_data = decrypted_padded_plaintext.rstrip(b'\x00')

        return decrypted_data
    
    if algo == '3DES':
        iv = key_dictionary[key_id]['iv']
        cipher = key_dictionary[key_id]['cipher']
        decryptor = cipher.decryptor()
        
        decrypted_padded_data = decryptor.update(cipher_text) + decryptor.finalize()
        # Remove padding
        unpadder = padding.PKCS7(len(key)*8).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        return decrypted_data
    
    if algo == 'RSA':
        decrypted_data = key.decrypt(
            cipher_text,
            paddingAs.OAEP(
                mgf=paddingAs.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_data
    

app = Flask(__name__)

@app.route('/generate-key', methods=['POST'])
def generating_key():
    print(request.form)
    algo = request.form['key_type']
    keySize = request.form['key_size']
    key = base64.b64encode(generateKey(algo, int(keySize)))
    key_id = key_dictionary[-1]['id']
    return jsonify({'key_id':key_id, 'key_value':str(key)})

@app.route('/encrypt', methods=['POST'])
def encrypt():
    algo = request.form['algorithm']
    key_id = request.form['key_id']
    data = request.form['plaintext']
    cipher_text = base64.b64encode(encryption(algo, int(key_id), data))
    return jsonify({'ciphertext':str(cipher_text)})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    algo = request.form['algorithm']
    key_id = request.form['key_id']
    cipher_text = request.form['ciphertext']
    ct = base64.b64decode(cipher_text[2:-1].encode('utf-8'))
    data = decryption(algo, int(key_id), ct)
    return jsonify({'plaintext':str(data.decode('utf-8'))})

if __name__ == '__main__':
    app.run(debug=True)