import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as paddingAs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding
from Crypto.Cipher import DES
from flask import Flask, request, jsonify
import base64
import sqlite3


def db_connection():
    conn = None
    try:
        conn = sqlite3.connect("key_database.sqlite") #connect to the database if not a database create a one
        # define the structure of the database
        cursor = conn.cursor()
        sql_query = ''' CREATE TABLE IF NOT EXISTS keys (
                    id INTEGER PRIMARY KEY,
                    private_key BLOB NOT NULL,
                    public_key BLOB,
                    algorithm TEXT NOT NULL,
                    iv BLOB
                ) '''
        cursor.execute(sql_query)
        return conn
    except sqlite3.Error as e:
        print(e)
        return None
    
def generateKey(algo, keySize, conn):
    cursor = conn.cursor()
    if algo == ('AES' or 'DES' or '3DES'):
        key = os.urandom(int(keySize/8))

        sql_query = ''' INSERT INTO keys (private_key, algorithm) VALUES (?, ?) '''
        cursor.execute(sql_query, (key, algo,))
        conn.commit()

        return base64.b64encode(key), cursor
    
    if algo == 'RSA':
        
        private_key = rsa.generate_private_key(
            public_exponent=65537, #a prime number such as being relatively prime to 𝜙(𝑛)=(p-1)x(q-1) ,p,q prime of n 
            key_size= keySize,
        )
        public_key = private_key.public_key()
       
        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
                
        sql_query = ''' INSERT INTO keys (private_key, algorithm, public_key) VALUES (?, ?, ?) '''
        cursor.execute(sql_query, (private_pem, algo, public_pem))
        conn.commit()
        return private_pem.decode("utf-8"), cursor
    
def encryption(algo, key_id, data, conn):

    data = data.encode('utf-8')
    cursor = conn.cursor()
    cursor.execute("SELECT private_key FROM keys WHERE id = ?", (key_id,))
    key = cursor.fetchone()[0]
    ksize = len(key)
    
    if algo == 'AES':
        # Generate a random Initialization Vector (IV)
        iv = os.urandom(int(128/8))  # IV should be unique for each encryption 16 bit fixed size (AES blocksize is 128 bits)
        cursor.execute("UPDATE keys SET iv = ? WHERE id = ?", (iv, key_id))
        conn.commit()

        # Padding data to fit block size (16 bytes for AES)
        padder = padding.PKCS7(ksize*8).padder()  # Block size is 128 bits = 16 bytes
        padded_data = padder.update(data) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return ct
    
    if algo == 'DES':
        # Generate a random Initialization Vector (IV)
        iv = os.urandom(int(64/8))  # IV should be unique for each encryption 16 bit fixed size (DES blocksize is 64 bits)
        cursor.execute("UPDATE keys SET iv = ? WHERE id = ?", (iv, key_id))
        conn.commit()

        # Create DES cipher in CBC mode
        cipher = DES.new(key, DES.MODE_CBC, iv)
        
        padded_plaintext = data.ljust(128, b'\x00')  # Pad to 16 bytes
        ct = cipher.encrypt(padded_plaintext)

        return ct
    
    if algo == '3DES':
        iv = os.urandom(int(64/8))  # IV should be unique for each encryption 16 bit fixed size (DES blocksize is 64 bits)
        cursor.execute("UPDATE keys SET iv = ? WHERE id = ?", (iv, key_id))
        conn.commit()

        # Padding data to fit block size (16 bytes for AES)
        padder = padding.PKCS7(ksize*8).padder()  # Block size is 128 bits = 16 bytes
        padded_data = padder.update(data) + padder.finalize()

        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
        
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return ct
    
    if algo == 'RSA':
        cursor.execute("SELECT public_key FROM keys WHERE id = ?", (key_id,))
        public_key = cursor.fetchone()[0]
        public_key = serialization.load_pem_public_key(public_key)

        ct = public_key.encrypt(
            data,
            paddingAs.OAEP(
                mgf=paddingAs.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ct

def decryption(algo, key_id, cipher_text, conn):
    cursor = conn.cursor()
    cursor.execute("SELECT private_key FROM keys WHERE id = ?", (key_id,))
    key = cursor.fetchone()[0]
    cursor.execute("SELECT iv FROM keys WHERE id = ?", (key_id,))
    iv = cursor.fetchone()[0]

    if algo == 'AES':
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(cipher_text) + decryptor.finalize()
        # Remove padding
        unpadder = padding.PKCS7(len(key)*8).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        return decrypted_data
    
    if algo == 'DES':
        
        decipher = DES.new(key, DES.MODE_CBC, iv)
       
        decrypted_padded_plaintext = decipher.decrypt(cipher_text)
        decrypted_data = decrypted_padded_plaintext.rstrip(b'\x00')

        return decrypted_data
    
    if algo == '3DES':

        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
    
        decryptor = cipher.decryptor()
        
        decrypted_padded_data = decryptor.update(cipher_text) + decryptor.finalize()
        # Remove padding
        unpadder = padding.PKCS7(len(key)*8).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        return decrypted_data
    
    if algo == 'RSA':
        key = serialization.load_pem_private_key(
            key,
            password=None
        )
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
    conn = db_connection() #connect to the database
    cursor = conn.cursor() #create a cursor object using the cursor() method to execute SQL queries

    algo = request.form['key_type']
    keySize = request.form['key_size']
    key, cursor = generateKey(algo, int(keySize), conn)
    key_id = cursor.lastrowid

    return jsonify({'key_id':key_id, 'key_value':str(key)})

@app.route('/encrypt', methods=['POST'])
def encrypt():
    conn = db_connection() #connect to the database
    cursor = conn.cursor()

    algo = request.form['algorithm']
    key_id = request.form['key_id']
    data = request.form['plaintext']
    cipher_text = base64.b64encode(encryption(algo, int(key_id), data, conn))
    return jsonify({'ciphertext':str(cipher_text)})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    conn = db_connection() #connect to the database
    cursor = conn.cursor()

    algo = request.form['algorithm']
    key_id = request.form['key_id']
    cipher_text = request.form['ciphertext']
    ct = base64.b64decode(cipher_text[2:-1].encode('utf-8'))
    data = decryption(algo, int(key_id), ct, conn)
    return jsonify({'plaintext':str(data.decode('utf-8'))})

if __name__ == '__main__':
    app.run(debug=True)