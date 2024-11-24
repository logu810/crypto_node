from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import numpy as np
import os
from util.public_key import PublicKey
from util.secret_key import SecretKey
from util.polynomial import Polynomial
from lattice_crypto import generate_keys, encrypt_ckks, decrypt_ckks, sum_columns, prepare_input, decrypt_columns
import json

app = Flask(__name__)
CORS(app)

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

ANALYSIS_DIR = "analysis"
os.makedirs(ANALYSIS_DIR, exist_ok=True)

DECRYPTED_DIR = "decrypted"
os.makedirs(DECRYPTED_DIR, exist_ok=True)

@app.route('/generate-key', methods=['POST'])
def generate_key_route():
    secret_key, public_key = generate_keys()
    return jsonify({
        "public_key": public_key.to_dict(),
        "secret_key": secret_key.__str__(),
    })

@app.route('/upload-file', methods=['POST'])
def upload_file():
    file = request.files['file']
    public_key_data = json.loads(request.form['public_key'])
    secret_key_data = json.loads(request.form['secret_key'])

    p0_deg,p0_coef = Polynomial.parse_polynomial(public_key_data['p0'])
    p1_deg,p1_coef = Polynomial.parse_polynomial(public_key_data['p1'])
    print(type(request.form['public_key']),request.form['public_key'])

    p0 = Polynomial(p0_deg+1, p0_coef)
    p1 = Polynomial(p1_deg+1, p1_coef)

    public_key = PublicKey(p0,p1)
    print(public_key.__str__())

    sec_deg,sec_coef = Polynomial.parse_secret_polynomial(secret_key_data)
    sec = Polynomial(sec_deg+1, sec_coef)
    secret_key = SecretKey(sec)

    print("secret",sec_deg,sec_coef,secret_key.__str__())
    
    df = pd.read_csv(file)
    df = df.apply(pd.to_numeric, errors="coerce").fillna(0)

    encrypted_df = df.apply(lambda row: encrypt_ckks(prepare_input(row), public_key, secret_key), axis=1)
    encrypted_file_path = os.path.join(DATA_DIR, f"encrypted_{file.filename}")
    
    encrypted_df.to_csv(encrypted_file_path, index=False)
    return jsonify({"message": "File encrypted and saved successfully."})

@app.route('/analyze/<filename>', methods=['POST'])
def analyze_file(filename):
    encrypted_file_path = os.path.join(DATA_DIR, f"encrypted_{filename}")
    df = pd.read_csv(encrypted_file_path)

    result_df = sum_columns(df)
    analysed_file_path = os.path.join(ANALYSIS_DIR, f"analysed_{filename}")
    
    result_df.to_csv(analysed_file_path, index=False)
    return jsonify({"message": "File analysed and saved successfully."})

@app.route('/decrypt/<filename>', methods=['POST'])
def decrypt_file(filename):

    analysed_file_path = os.path.join(ANALYSIS_DIR, f"analysed_{filename}")
    df = pd.read_csv(analysed_file_path)
 
    secret_key_data = request.json.get('secret_key')
    sec_deg,sec_coef = Polynomial.parse_secret_polynomial(secret_key_data)
    sec = Polynomial(sec_deg+1, sec_coef)
    secret_key = SecretKey(sec)
    
    decrypt_df = decrypt_columns(df,secret_key)
    print(secret_key)
    decrtpted_file_path = os.path.join(DECRYPTED_DIR, f"decrypted_{filename}")
    
    decrypt_df.to_csv(decrtpted_file_path, index=False)
    return jsonify({"message": "File decrypted and saved successfully."})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
