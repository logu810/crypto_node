"""Example of CKKS multiplication."""

from ckks.ckks_decryptor import CKKSDecryptor
from ckks.ckks_encoder import CKKSEncoder
from ckks.ckks_encryptor import CKKSEncryptor
from ckks.ckks_evaluator import CKKSEvaluator
from ckks.ckks_key_generator import CKKSKeyGenerator
from ckks.ckks_parameters import CKKSParameters

def main():

    poly_degree = 8
    ciph_modulus = 1 << 600
    big_modulus = 1 << 1200
    scaling_factor = 1 << 30
    params = CKKSParameters(poly_degree=poly_degree,
                            ciph_modulus=ciph_modulus,
                            big_modulus=big_modulus,
                            scaling_factor=scaling_factor)
    key_generator = CKKSKeyGenerator(params)
    public_key = key_generator.public_key
    secret_key = key_generator.secret_key
    relin_key = key_generator.relin_key
    encoder = CKKSEncoder(params)
    encryptor = CKKSEncryptor(params, public_key, secret_key)
   
    decryptor = CKKSDecryptor(params, secret_key)
    evaluator = CKKSEvaluator(params)

    message1 = [0.5, 0.3, 0.78, 0.88]
    message2 = [0.2, 0.11, 0.4 , 0.9 ]
    message3 = [0.2, 0.11, 0.4 , 0.9 ]
    message4 = [0.2, 0.11, 0.4 , 0.9 ]


    plain1 = encoder.encode(message1, scaling_factor)
    plain2 = encoder.encode(message2, scaling_factor)
    plain3 = encoder.encode(message3, scaling_factor)
    plain4 = encoder.encode(message4, scaling_factor)

    ciph1 = encryptor.encrypt(plain1)
    ciph2 = encryptor.encrypt(plain2)
    ciph3 = encryptor.encrypt(plain3)
    ciph4 = encryptor.encrypt(plain4)
    
    print(type(ciph1))

    ciph_sum1 = evaluator.add(ciph1, ciph2)
    ciph_sum2 = evaluator.add(ciph3, ciph4)
    ciph_sum = evaluator.add(ciph_sum1, ciph_sum2)

    decrypted_prod = decryptor.decrypt(ciph_sum)
    decoded_prod = encoder.decode(decrypted_prod)
    
    print(decoded_prod)

if __name__ == '__main__':
    main()