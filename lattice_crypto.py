import numpy as np
from ckks.ckks_parameters import CKKSParameters
from ckks.ckks_key_generator import CKKSKeyGenerator
from ckks.ckks_encryptor import CKKSEncryptor
from ckks.ckks_decryptor import CKKSDecryptor
from ckks.ckks_evaluator import CKKSEvaluator
from ckks.ckks_encoder import CKKSEncoder
from util.polynomial import Polynomial
from util.ciphertext import Ciphertext
import pandas as pd
import json


# Initialize the CKKS parameters and encoder
def init_ckks_parameters():
    # poly_degree = 8  # Polynomial degree (power of 2)
    # ciph_modulus = 1 << 600  # Must be larger than plain modulus
    # big_modulus =  1 << 1200  
    # scaling_factor = 1 << 30
    params = CKKSParameters()

    encoder = CKKSEncoder(params)
    return params, encoder

# Key Generation Function
def generate_keys():
    params, _ = init_ckks_parameters()
    print(params)
    keygen = CKKSKeyGenerator(params)
    secret_key = keygen.secret_key
    public_key = keygen.public_key
    return secret_key, public_key

# Encryption Function for CKKS Scheme
def encrypt_ckks(plaintext, public_key, secret_key):
    params, encoder = init_ckks_parameters()
    print(params)
    encryptor = CKKSEncryptor(params, public_key, secret_key)
    encoded_plaintext = encoder.encode(plaintext, scaling_factor=params.scaling_factor)  # Convert to encoded format
    ciphertext = encryptor.encrypt(encoded_plaintext)
    return ciphertext.to_dict()

# Decryption Function for CKKS Scheme
def decrypt_ckks(ciphertext, secret_key):
    params, encoder = init_ckks_parameters()
    decryptor = CKKSDecryptor(params, secret_key)
    decrypted_ciphertext = decryptor.decrypt(ciphertext)
    decoded_data = encoder.decode(decrypted_ciphertext)
    return decoded_data[0]  # Assuming single value

def linear_regression_homomorphic(encrypted_data):
    """
    This simplified version of linear regression will perform homomorphic addition and multiplication on the
    encrypted data instead of solving for coefficients using full matrix operations.

    encrypted_data: An array where each row represents a data point with encrypted x and y values.
    """
    params, encoder = init_ckks_parameters()
    evaluator = CKKSEvaluator(params)
    
    # Separate encrypted data into X (x values) and y (y values)
    X_encrypted = encrypted_data[:, 0]  # Encrypted x values
    y_encrypted = encrypted_data[:, 1]  # Encrypted y values
    
    # Initialize homomorphic result arrays (will store encrypted results)
    sum_X = 0
    sum_y = 0
    sum_Xy = 0
    sum_X2 = 0

    # Perform homomorphic addition and multiplication on the encrypted data
    for x_enc, y_enc in zip(X_encrypted, y_encrypted):
        # Encrypted sum X
        sum_X += x_enc  # Homomorphic addition of encrypted x values
        sum_y += y_enc  # Homomorphic addition of encrypted y values
        
        # Encrypted sum of X*y
        sum_Xy += evaluator.multiply(x_enc, y_enc)  # Homomorphic multiplication of x and y
        
        # Encrypted sum of X^2
        sum_X2 += evaluator.multiply(x_enc, x_enc)  # Homomorphic multiplication of x with itself
    
    # Calculate the "coefficients" using basic homomorphic operations
    slope_encrypted = evaluator.divide(sum_Xy, sum_X2)  # Simplified calculation (homomorphic division)
    intercept_encrypted = evaluator.subtract(sum_y, evaluator.multiply(slope_encrypted, sum_X))
    
    # These coefficients are encrypted (as the operations were homomorphic)
    encrypted_coefficients = np.array([slope_encrypted, intercept_encrypted])
    
    return encrypted_coefficients


def prepare_input(row):
    # Convert row to list and ensure it's of length 4
    input_list = row.tolist()
    if len(input_list) < 4:
        input_list += [0] * (4 - len(input_list))  # Pad with zeros if less than 4
    elif len(input_list) > 4:
        input_list = input_list[:4]  # Trim if more than 4
    return input_list


def sum_columns(df):

    params, _ = init_ckks_parameters()
    evaluator = CKKSEvaluator(params)

    # Initialize an empty DataFrame for results
    result_df = pd.DataFrame(columns=df.columns)
    
    # Iterate over each column in the DataFrame
    for column in df.columns:
        # Extract the column values as a list
        column_values = df[column].tolist()
        print(type(column_values[0]),column_values[0])


        first_val = json.loads(column_values[0].replace("'", '"'))
        # Reset cumulative sum for the current column
        c0_deg,c0_coef = Polynomial.parse_polynomial(first_val['c0'])
        c1_deg,c1_coef = Polynomial.parse_polynomial(first_val['c1'])

        c0 = Polynomial(c0_deg+1, c0_coef)
        c1 = Polynomial(c1_deg+1, c1_coef)

        cumulative_sum = Ciphertext(c0,c1)
        
        for i in range(1,len(column_values)):
            val =  json.loads(column_values[i].replace("'", '"'))
            c0_deg,c0_coef = Polynomial.parse_polynomial(val['c0'])
            c1_deg,c1_coef = Polynomial.parse_polynomial(val['c1'])

            c0 = Polynomial(c0_deg+1, c0_coef)
            c1 = Polynomial(c1_deg+1, c1_coef)

            value = Ciphertext(c0,c1)
            # Add to cumulative sum using your custom addition function
            cumulative_sum = evaluator.add(cumulative_sum, value)
        
        # Append the cumulative sum to the result DataFrame
        result_df[column] = pd.Series(str(cumulative_sum.to_dict()))
    
    return result_df

def mul_columns(df):

    params, _ = init_ckks_parameters()
    evaluator = CKKSEvaluator(params)

    # Initialize an empty DataFrame for results
    result_df = pd.DataFrame(columns=df.columns)
    
    # Iterate over each column in the DataFrame
    for column in df.columns:
        # Extract the column values as a list
        column_values = df[column].tolist()
        print(type(column_values[0]),column_values[0])


        first_val = json.loads(column_values[0].replace("'", '"'))
        # Reset cumulative sum for the current column
        c0_deg,c0_coef = Polynomial.parse_polynomial(first_val['c0'])
        c1_deg,c1_coef = Polynomial.parse_polynomial(first_val['c1'])

        c0 = Polynomial(c0_deg+1, c0_coef)
        c1 = Polynomial(c1_deg+1, c1_coef)

        cumulative_sum = Ciphertext(c0,c1)
        
        for i in range(1,len(column_values)):
            val =  json.loads(column_values[i].replace("'", '"'))
            c0_deg,c0_coef = Polynomial.parse_polynomial(val['c0'])
            c1_deg,c1_coef = Polynomial.parse_polynomial(val['c1'])

            c0 = Polynomial(c0_deg+1, c0_coef)
            c1 = Polynomial(c1_deg+1, c1_coef)

            value = Ciphertext(c0,c1)
            # Add to cumulative sum using your custom addition function
            cumulative_sum = evaluator.multiply(cumulative_sum, value)
        
        # Append the cumulative sum to the result DataFrame
        result_df[column] = pd.Series(str(cumulative_sum.to_dict()))
    
    return result_df

def decrypt_columns(df, secret_key):
    params, _ = init_ckks_parameters()
    decryptor = CKKSDecryptor(params, secret_key)
    encoder = CKKSEncoder(params)

    decrypted_df = pd.DataFrame(columns=df.columns)

    for column in df.columns:
        column_values = df[column].tolist()
        for i in column_values:
            print(i)
            val =  json.loads(i.replace("'", '"'))
            c0_deg,c0_coef = Polynomial.parse_polynomial(val['c0'])
            c1_deg,c1_coef = Polynomial.parse_polynomial(val['c1'])

            c0 = Polynomial(c0_deg+1, c0_coef)
            c1 = Polynomial(c1_deg+1, c1_coef)

            value = Ciphertext(c0,c1)
            decrypted_value = decryptor.decrypt(value)
            decoded_value = encoder.decode(decrypted_value)

        decrypted_df.at[0,column] = decoded_value[0]

    return decrypted_df







