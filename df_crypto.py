import numpy as np
import pandas as pd
import json
import time 
from ckks.ckks_parameters import CKKSParameters
from ckks.ckks_key_generator import CKKSKeyGenerator
from ckks.ckks_encryptor import CKKSEncryptor
from ckks.ckks_decryptor import CKKSDecryptor
from ckks.ckks_evaluator import CKKSEvaluator
from ckks.ckks_encoder import CKKSEncoder
from util.polynomial import Polynomial
from util.ciphertext import Ciphertext



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
    while 1:
        ciphertext = encryptor.encrypt(encoded_plaintext)
        
        if any(elem in ciphertext.c0.coeffs for elem in (1,0,-1)) or any(elem in ciphertext.c1.coeffs for elem in (1,0,-1)):
            print("not valid",ciphertext.__str__())
            
        else:
            print("valid",ciphertext.__str__())
            break


    return ciphertext.to_dict()

# Decryption Function for CKKS Scheme
def decrypt_ckks(ciphertext, secret_key):
    params, encoder = init_ckks_parameters()
    decryptor = CKKSDecryptor(params, secret_key)
    decrypted_ciphertext = decryptor.decrypt(ciphertext)
    decoded_data = encoder.decode(decrypted_ciphertext)
    return decoded_data[0]  # Assuming single value

def prepare_input(row):
    # Convert row to list and ensure it's of length 4
    print(row,type(row))
    input_list = [float(row)]*4

    if len(input_list) < 4:
        input_list += [0] * (4 - len(input_list))  # Pad with zeros if less than 4
    elif len(input_list) > 4:
        input_list = input_list[:4]  # Trim if more than 4
    print(input_list,type(input_list),type(input_list[0]))
    return input_list


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

def process_dataframe(df):
    # Step 1: Remove the last row
    print(df)
    df = df.iloc[:-1]  # Remove the last row

    # Step 2: Remove complex terms and round off to 5 decimal places
    for column in df.columns:
        df[column] = df[column].apply(lambda x: round(x.real, 5))  # Keep only the real part and round

    # Step 3: Calculate mean, std deviation, and variance
    sum = df.sum().round(5)
    means = df.mean().round(5)  # Calculate mean and round to 5 decimal places
    std_devs = df.std().round(5)  # Calculate standard deviation and round to 5 decimal places
    variances = df.var().round(5)  # Calculate variance and round to 5 decimal places

    # Step 4: Create a new DataFrame for the statistics
    stats_df = pd.DataFrame({
        'Sum' : sum,
        'Mean': means,
        'Standard Deviation': std_devs,
        'Variance': variances
    })

    # Append the statistics as a new row to the original DataFrame
    stats_df.index.name = 'Statistics'  # Set index name for clarity
    df = pd.concat([df, stats_df.T], ignore_index=False)

    return df

def decrypt_columns(df, secret_key):
    params, _ = init_ckks_parameters()
    decryptor = CKKSDecryptor(params, secret_key)
    encoder = CKKSEncoder(params)

    # Initialize metrics
    total_decryption_time = 0
    num_rows = len(df)
    num_columns = len(df.columns)

    # Initialize an empty DataFrame for decrypted results
    decrypted_df = pd.DataFrame(columns=df.columns)

    # Decrypt each column
    for column in df.columns:
        column_values = df[column].tolist()
        decrypted_column_values = []  # List to hold decrypted values for the current column

        for value in column_values:
            # Start timing the decryption process
            start_time = time.time()

            val = json.loads(value.replace("'", '"'))
            c0_deg, c0_coef = Polynomial.parse_polynomial(val['c0'])
            c1_deg, c1_coef = Polynomial.parse_polynomial(val['c1'])

            c0 = Polynomial(c0_deg + 1, c0_coef)
            c1 = Polynomial(c1_deg + 1, c1_coef)

            ciphertext = Ciphertext(c0, c1)
            decrypted_value = decryptor.decrypt(ciphertext)
            decoded_value = encoder.decode(decrypted_value)

            # Stop timing and record time
            elapsed_time = time.time() - start_time
            total_decryption_time += elapsed_time

            # Append the decoded value to the list
            decrypted_column_values.append(decoded_value[0])  # Assuming decoded_value is a list

        # Assign the decrypted values back to the DataFrame
        decrypted_df[column] = decrypted_column_values

    # Calculate metrics
    avg_decryption_time_per_row = total_decryption_time / num_rows
    avg_decryption_time_per_value = total_decryption_time / (num_rows * num_columns)

    # Print metrics
    print(f"Total decryption time: {total_decryption_time:.2f} seconds")
    print(f"Average decryption time per row: {avg_decryption_time_per_row:.4f} seconds/row")
    print(f"Average decryption time per value: {avg_decryption_time_per_value:.6f} seconds/value")

    return decrypted_df



def sum_columns(df):
    params, _ = init_ckks_parameters()
    evaluator = CKKSEvaluator(params)

    # Metrics initialization
    total_addition_time = 0
    num_rows = len(df)
    num_columns = len(df.columns)

    # Initialize a list to hold cumulative sums for each column
    cumulative_sums = {column: [] for column in df.columns}

    # Iterate over each column in the DataFrame
    column_addition_times = []  # Track addition time per column

    for column in df.columns:
        column_values = df[column].tolist()

        # Parse the first value to initialize cumulative sum
        first_val = json.loads(column_values[0].replace("'", '"'))
        c0_deg, c0_coef = Polynomial.parse_polynomial(first_val['c0'])
        c1_deg, c1_coef = Polynomial.parse_polynomial(first_val['c1'])

        c0 = Polynomial(c0_deg + 1, c0_coef)
        c1 = Polynomial(c1_deg + 1, c1_coef)
        cumulative_sum = Ciphertext(c0, c1)

        # Time addition for this column
        column_addition_time = 0

        # Sum up all the values in the column
        for i in range(1, len(column_values)):
            val = json.loads(column_values[i].replace("'", '"'))
            c0_deg, c0_coef = Polynomial.parse_polynomial(val['c0'])
            c1_deg, c1_coef = Polynomial.parse_polynomial(val['c1'])

            c0 = Polynomial(c0_deg + 1, c0_coef)
            c1 = Polynomial(c1_deg + 1, c1_coef)
            value = Ciphertext(c0, c1)

            # Start timing the addition process
            start_time = time.time()

            cumulative_sum = evaluator.add(cumulative_sum, value)

            # Stop timing and record time
            elapsed_time = time.time() - start_time
            column_addition_time += elapsed_time
            total_addition_time += elapsed_time

        # Append the current column addition time
        column_addition_times.append(column_addition_time)

        # Append the current cumulative sum to the list
        cumulative_sums[column].append(str(cumulative_sum.to_dict()))

    # Create a new DataFrame from cumulative sums
    cumulative_df = pd.DataFrame(cumulative_sums)

    # Append the cumulative sums DataFrame as new rows to the existing DataFrame
    df = pd.concat([df, cumulative_df], ignore_index=True)

    # Calculate metrics
    avg_addition_time_per_row = total_addition_time / num_rows
    avg_addition_time_per_value = total_addition_time / (num_rows * num_columns)
    avg_addition_time_per_column = total_addition_time / num_columns

    # Print metrics
    print(f"Total homomorphic addition time: {total_addition_time:.2f} seconds")
    print(f"Average addition time per row: {avg_addition_time_per_row:.4f} seconds/row")
    print(f"Average addition time per value: {avg_addition_time_per_value:.6f} seconds/value")
    print(f"Average addition time per column: {avg_addition_time_per_column:.4f} seconds/column")

    # Optionally print per-column addition times for debugging
    for idx, time1 in enumerate(column_addition_times):
        print(f"Column {df.columns[idx]} addition time: {time1:.4f} seconds")

    return df



