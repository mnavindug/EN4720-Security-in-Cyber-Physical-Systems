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
from hashlib import sha256, sha512

app = Flask(__name__)


def db_connection():
    conn = None
    try:
        # connect to the database if not a database create a one
        conn = sqlite3.connect("key_database.sqlite")
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


def generateKey(algorithm, keySize, conn):
    cursor = conn.cursor()
    if isinstance(keySize, str):
        keySize = int(keySize)
    if algorithm in ['AES', 'DES', '3DES']:
        if algorithm == 'AES':
            if keySize not in [128, 192, 256]:
                return jsonify({"error": "Invalid key size for AES. Must be 128, 192, or 256 bits."}), 400
            else:
                key = os.urandom(int(keySize/8))
        elif algorithm == 'DES':
            if keySize not in [56, 64]:
                return jsonify({"error": "Invalid key size for DES. Must be 56, or 64 bits."}), 400
            else:
                key = os.urandom(8)
        elif algorithm == '3DES':
            if keySize not in [56, 64, 112, 128, 168, 192]:
                return jsonify({"error": f"Invalid key size for 3DES. Must be 56, 64, 112, 128, 168, or 192 bits."}), 400
            else:
                size_map = {56: 8, 64: 8, 112: 16, 128: 16, 168: 24, 192: 24}
                key = os.urandom(size_map[keySize])
        else:
            return jsonify({"error": "Unsupported key generation algorithm"}), 400
        key_b64 = base64.b64encode(key).decode()
        sql_query = ''' INSERT INTO keys (private_key, algorithm) VALUES (?, ?) '''
        cursor.execute(sql_query, (key_b64, algorithm,))
        conn.commit()
        key_id = cursor.lastrowid
        return jsonify({'key_id': key_id, 'key_value': key_b64})

    elif algorithm == 'RSA':
        if keySize not in [1024, 2048, 3072, 4096]:
            return jsonify({"error": "Invalid key size for RSA. Must be 1024, 2048, 3072, or 4096 bits."}), 400
        private_key = rsa.generate_private_key(
            # a prime number such as being relatively prime to 𝜙(𝑛)=(p-1)x(q-1) ,p,q prime of n
            public_exponent=65537,
            key_size=keySize,
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
        private_key_b64 = base64.b64encode(private_pem).decode()
        public_key_b64 = base64.b64encode(public_pem).decode()
        sql_query = ''' INSERT INTO keys (private_key, algorithm, public_key) VALUES (?, ?, ?) '''
        cursor.execute(sql_query, (private_key_b64, algorithm, public_key_b64))
        conn.commit()
        key_id = cursor.lastrowid
        return jsonify({'key_id': key_id, 'key_value': private_key_b64})
    else:
        return jsonify({"error": "Unsupported key generation algorithm"}), 400


def encryption(algorithm, key_id, plaintext, conn):
    plaintext = plaintext.encode()
    cursor = conn.cursor()
    cursor.execute("SELECT private_key FROM keys WHERE id = ?", (key_id,))
    result = cursor.fetchone()
    if result is None:
        return None, jsonify({"error": f"Key ID {key_id} not found"}), 404
    key = result[0]
    key = base64.b64decode(key)

    if algorithm == 'AES':
        # Generate a random Initialization Vector (IV)
        # regardless of the key size, the IV is always 16 bytes for AES
        iv = os.urandom(algorithms.AES.block_size//8)
        cursor.execute("UPDATE keys SET iv = ? WHERE id = ?", (iv, key_id))
        conn.commit()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_plaintext) + encryptor.finalize()

    elif algorithm == 'DES':
        # Generate a random Initialization Vector (IV)
        # regardless of the key size, the IV is always 8 bytes for DES
        iv = os.urandom(64//8)
        cursor.execute("UPDATE keys SET iv = ? WHERE id = ?", (iv, key_id))
        conn.commit()
        padder = padding.PKCS7(64).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        # Create DES cipher in CBC mode
        cipher = DES.new(key, DES.MODE_CBC, iv)
        ct = cipher.encrypt(padded_plaintext)

    elif algorithm == '3DES':
        # Generate a random Initialization Vector (IV)
        # regardless of the key size, the IV is always 8 bytes for 3DES
        iv = os.urandom(algorithms.TripleDES.block_size//8)
        cursor.execute("UPDATE keys SET iv = ? WHERE id = ?", (iv, key_id))
        conn.commit()
        padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_plaintext) + encryptor.finalize()

    elif algorithm == 'RSA':
        cursor.execute("SELECT public_key FROM keys WHERE id = ?", (key_id,))
        result = cursor.fetchone()
        if result is None:
            return jsonify({"error": f"Public key not found for Key ID {key_id}"}), 400
        public_key = result[0]
        public_key = base64.b64decode(public_key)
        public_key = serialization.load_pem_public_key(public_key)
        ct = public_key.encrypt(
            plaintext,
            paddingAs.OAEP(
                mgf=paddingAs.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    else:
        return jsonify({"error": "Unsupported encryption algorithm"}), 400
    ct_b64 = base64.b64encode(ct).decode()
    return jsonify({'ciphertext': ct_b64})


def decryption(algorithm, key_id, cipher_text, conn):
    cursor = conn.cursor()
    cursor.execute("SELECT private_key FROM keys WHERE id = ?", (key_id,))
    result = cursor.fetchone()
    if result is None:
        return jsonify({"error": f"Key ID {key_id} not found"}), 400
    key = result[0]
    if algorithm in ['AES', 'DES', '3DES']:
        cursor.execute("SELECT iv FROM keys WHERE id = ?", (key_id,))
        result = cursor.fetchone()
        if result is None:
            return jsonify({"error": f"IV not found for Key ID {key_id}"}), 400
        iv = result[0]
    cipher_text = base64.b64decode(cipher_text)
    key = base64.b64decode(key)

    if algorithm == 'AES':
        decipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = decipher.decryptor()
        decrypted_padded_plaintext = decryptor.update(
            cipher_text) + decryptor.finalize()
        # Remove padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(
            decrypted_padded_plaintext) + unpadder.finalize()

    elif algorithm == 'DES':
        decipher = DES.new(key, DES.MODE_CBC, iv)
        decrypted_padded_plaintext = decipher.decrypt(cipher_text)
        # Remove padding
        unpadder = padding.PKCS7(64).unpadder()
        decrypted_data = unpadder.update(
            decrypted_padded_plaintext) + unpadder.finalize()

    elif algorithm == '3DES':
        decipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
        decryptor = decipher.decryptor()
        decrypted_padded_plaintext = decryptor.update(
            cipher_text) + decryptor.finalize()
        # Remove padding
        unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
        decrypted_data = unpadder.update(
            decrypted_padded_plaintext) + unpadder.finalize()

    elif algorithm == 'RSA':
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
    else:
        return jsonify({"error": "Unsupported encryption algorithm"}), 400
    return jsonify({'plaintext': str(decrypted_data.decode())})


@app.route('/generate-key', methods=['POST'])
def generating_key():
    conn = db_connection()  # connect to the database
    data = request.json
    algorithm = data.get('key_type')
    keySize = data.get('key_size')
    print(algorithm, keySize)
    return generateKey(algorithm, keySize, conn)


@app.route('/encrypt', methods=['POST'])
def encrypt():
    conn = db_connection()  # connect to the database
    data = request.json
    algorithm = data.get('algorithm')
    key_id = data.get('key_id')
    plaintext = data.get('plaintext')
    return encryption(algorithm, key_id, plaintext, conn)


@app.route('/decrypt', methods=['POST'])
def decrypt():
    conn = db_connection()  # connect to the database
    data = request.json
    algorithm = data.get('algorithm')
    key_id = data.get('key_id')
    cipher_text = data.get('ciphertext')
    return decryption(algorithm, key_id, cipher_text, conn)


@app.route("/generate-hash", methods=["POST"])
def generate_hash():
    data = request.json
    input_data = data.get("data")
    algorithm = data.get("algorithm")

    if algorithm.upper() == "SHA-256":
        hash_value = sha256(input_data.encode()).digest()
    elif algorithm.upper() == "SHA-512":
        hash_value = sha512(input_data.encode()).digest()
    else:
        return jsonify({"error": "Unsupported hash algorithm"}), 400

    return jsonify({
        "hash_value": base64.b64encode(hash_value).decode(),
        "algorithm": algorithm
    })


@app.route("/verify-hash", methods=["POST"])
def verify_hash():
    data = request.json
    input_data = data.get("data")
    hash_value = data.get("hash_value")
    algorithm = data.get("algorithm")

    if algorithm.upper() == "SHA-256":
        expected_hash = sha256(input_data.encode()).digest()
    elif algorithm.upper() == "SHA-512":
        expected_hash = sha512(input_data.encode()).digest()
    else:
        return jsonify({"error": "Unsupported hash algorithm"}), 400

    is_valid = base64.b64encode(expected_hash).decode() == hash_value

    return jsonify({
        "is_valid": is_valid,
        "message": "Hash matches the data." if is_valid else "Hash does not match."
    })


if __name__ == '__main__':
    app.run(debug=True)
