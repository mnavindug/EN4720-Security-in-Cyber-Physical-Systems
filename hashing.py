from flask import Flask, request, jsonify
import base64
from hashlib import sha256, sha512

app = Flask(__name__)

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
        "hash_value" : base64.b64encode(hash_value).decode(),
        "algorithm" : algorithm
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
        "message": "Hash matches" if is_valid else "Hash does not match"
    })