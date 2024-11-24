from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import pandas as pd
import numpy as np
import os
from util.public_key import PublicKey
from util.secret_key import SecretKey
from util.polynomial import Polynomial
from lattice_crypto import generate_keys, encrypt_ckks, sum_columns, prepare_input, decrypt_columns, process_dataframe
import json

app = Flask(__name__)
CORS(app)

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

ANALYSIS_DIR = "analysis"
os.makedirs(ANALYSIS_DIR, exist_ok=True)

DECRYPTED_DIR = "decrypted"
os.makedirs(DECRYPTED_DIR, exist_ok=True)

SECRET_DIR = "secrets"
os.makedirs(SECRET_DIR, exist_ok=True)

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

    p0_deg, p0_coef = Polynomial.parse_polynomial(public_key_data['p0'])
    p1_deg, p1_coef = Polynomial.parse_polynomial(public_key_data['p1'])

    p0 = Polynomial(p0_deg + 1, p0_coef)
    p1 = Polynomial(p1_deg + 1, p1_coef)

    public_key = PublicKey(p0, p1)

    sec_deg, sec_coef = Polynomial.parse_secret_polynomial(secret_key_data)
    sec = Polynomial(sec_deg + 1, sec_coef)
    secret_key = SecretKey(sec)

    # Read and process the uploaded CSV file
    df = pd.read_csv(file)
    df = df.apply(pd.to_numeric, errors="coerce").fillna(0)

    # Encrypt all columns
    encrypted_data = []
    
    for index, row in df.iterrows():
        encrypted_row = {}
        for column in df.columns:
            # Encrypt each column value
            encrypted_value = encrypt_ckks(prepare_input(row[column]), public_key, secret_key)
            encrypted_row[column] = encrypted_value
        encrypted_data.append(encrypted_row)

    # Convert list of encrypted rows to DataFrame
    encrypted_df = pd.DataFrame(encrypted_data)

    # Save the encrypted data to a CSV file
    encrypted_file_path = os.path.join(DATA_DIR, f"{file.filename}")
    encrypted_df.to_csv(encrypted_file_path, index=False)

    # Prepare to append filename and secret key to secret_key_df
    secret_key_df_path = os.path.join(SECRET_DIR, 'secret_keys.csv')

    # Check if the CSV already exists
    if os.path.exists(secret_key_df_path):
        # Load existing data
        secret_key_df = pd.read_csv(secret_key_df_path)
    else:
        # Create a new DataFrame if it doesn't exist
        secret_key_df = pd.DataFrame(columns=['filename', 'secret_key'])

    # Create a new DataFrame for the new entry
    new_entry_df = pd.DataFrame({'filename': [file.filename], 'secret_key': [sec.__str__()]})

    # Concatenate the existing DataFrame with the new entry
    secret_key_df = pd.concat([secret_key_df, new_entry_df], ignore_index=True)

    # Save updated DataFrame back to CSV
    secret_key_df.to_csv(secret_key_df_path, index=False)

    return jsonify({"message": "File encrypted and saved successfully."})

@app.route('/analyze/<filename>', methods=['POST'])
def analyze_file(filename):
    encrypted_file_path = os.path.join(DATA_DIR, f"{filename}")
    df = pd.read_csv(encrypted_file_path)

    result_df = sum_columns(df)
    analysed_file_path = os.path.join(ANALYSIS_DIR, f"{filename}")
    
    result_df.to_csv(analysed_file_path, index=False)
    return jsonify({"message": "File analysed and saved successfully."})

@app.route('/decrypt/<filename>', methods=['POST'])
def decrypt_file(filename):

    analysed_file_path = os.path.join(ANALYSIS_DIR, f"{filename}")
    df = pd.read_csv(analysed_file_path)
 
    secret_key_data = request.json.get('secret_key')
    sec_deg,sec_coef = Polynomial.parse_secret_polynomial(secret_key_data)
    sec = Polynomial(sec_deg+1, sec_coef)
    secret_key = SecretKey(sec)
    
    decrypt_df = decrypt_columns(df,secret_key)
    print(secret_key)
    processed_df = process_dataframe(decrypt_df)
    decrtpted_file_path = os.path.join(DECRYPTED_DIR, f"{filename}")
    
    processed_df.to_csv(decrtpted_file_path, index=False)
    return jsonify({"message": "File decrypted and saved successfully."})

@app.route('/files/<folder>', methods=['GET'])
def get_files(folder):
    # Determine the directory based on the folder parameter
    if folder not in ['data', 'analysis']:
        return jsonify({"error": "Invalid folder name"}), 400
    
    folder_path = os.path.join(os.getcwd(), folder)  # Get the absolute path of the folder

    # Check if the directory exists
    if not os.path.exists(folder_path):
        return jsonify({"error": "Folder not found"}), 404

    try:
        # List all files in the directory
        files = os.listdir(folder_path)
        return jsonify(files)  # Return the list of files as JSON
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    return send_from_directory(DECRYPTED_DIR, filename, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
