from flask import Flask, render_template, request, jsonify, url_for
import datetime
import hashlib
import json
from cryptography.fernet import Fernet, InvalidToken
import pickle
import base64
from encryption_utils import generate_rsa_key_pair, encrypt_rsa, decrypt_rsa, generate_aes_key, encrypt_aes, decrypt_aes

app = Flask(__name__)

# Blockchain Class
class Blockchain:
    def __init__(self):
        self.chain = []
        self.load_chain_from_file()  # Load the blockchain from file on initialization
        if not self.chain:
            # If the chain is empty (first run), create the initial block
            self.create_block(proof=1, previous_hash='0', user_id=None, medical_records=None, aes_key=None)

    def create_block(self, proof, previous_hash, user_id, medical_records, aes_key):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.datetime.now()),
            'proof': proof,
            'previous_hash': previous_hash,
            'user_id': user_id,
            'medical_records': medical_records, 
            'aes_key': aes_key
        }
        self.chain.append(block)
        self.save_chain_to_file()
        return block

    def save_chain_to_file(self):
        with open('blockchain.pkl', 'wb') as file:
            pickle.dump(self.chain, file)

    def load_chain_from_file(self):
        try:
            with open('blockchain.pkl', 'rb') as file:
                self.chain = pickle.load(file)
        except (FileNotFoundError, EOFError):
            # Handle the case where the file doesn't exist or is empty
            self.chain = []

    def print_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False

        while check_proof is False:
            hash_operation = hashlib.sha256(
                str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:5] == '00000':
                check_proof = True
            else:
                new_proof += 1

        return new_proof

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True, default=lambda x: x.decode('utf-8') if isinstance(x, bytes) else x).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1

        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False

            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(
                str(proof**2 - previous_proof**2).encode()).hexdigest()

            if hash_operation[:5] != '00000':
                return False
            previous_block = block
            block_index += 1

        return True


# Generate a key for encryption and decryption
user_private_key, user_public_key = generate_rsa_key_pair()

# Create the blockchain object
blockchain = Blockchain()

# Dashboard Routes
@app.route('/')
def dashboard():
    return render_template('dashboard.html')

# User Submission Route
@app.route('/submit_records', methods=['GET', 'POST'])
def submit_records():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        user_details = request.form.get('user_details')
        medical_records = request.form.get('medical_records')

        # Encrypt medical records with AES
        aes_key = generate_aes_key()
        encrypted_records_aes = encrypt_aes(aes_key, medical_records)

        # Encrypt AES key with user's public RSA key
        encrypted_aes_key = encrypt_rsa(user_public_key, aes_key)

        previous_block = blockchain.print_previous_block()
        previous_proof = previous_block['proof']
        proof = blockchain.proof_of_work(previous_proof)
        previous_hash = blockchain.hash(previous_block)

        # Create block with encrypted medical records and encrypted AES key
        block = blockchain.create_block(proof, previous_hash, user_id, medical_records=encrypted_records_aes, aes_key=encrypted_aes_key)

        response_data = {
            'message': 'Medical records submitted successfully',
            'user_id': user_id,
            'block_index': block['index'],
        }

        return render_template('response.html', **response_data)
    else:
        return render_template('submit_records.html')

valid_doctor_ids = {'doc1', 'doctor2'}

# Doctor Retrieval Route
@app.route('/retrieve_records', methods=['GET', 'POST'])
def retrieve_records():
    if request.method == 'POST':
        doctor_id = request.form.get('doctor_id')
        user_id = request.form.get('user_id')

        if doctor_id not in valid_doctor_ids:
            return jsonify({'error': 'Invalid doctor ID'}), 401

        user_records = []

        for block in blockchain.chain:
            if 'user_id' in block and block['user_id'] == user_id:
                # Decrypt AES key with user's private RSA key
                aes_key = decrypt_rsa(user_private_key, block['aes_key'])
                
                # Decrypt medical records with AES key
                medical_records = decrypt_aes(aes_key, block['medical_records'])
                
                user_records.append({
                    'index': block['index'],
                    'timestamp': block['timestamp'],
                    'user_id': block['user_id'],
                    'medical_records': medical_records
                })

        response_data = {
            'message': 'Medical records retrieved successfully',
            'doctor_id': doctor_id,
            'user_id': user_id,
            'medical_records': user_records
        }

        return render_template('retrieve_response.html', **response_data)
    else:
        return render_template('retrieve_records.html')

if __name__ == '__main__':
    app.run(debug=True)
