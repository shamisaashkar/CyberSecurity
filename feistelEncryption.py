import random

S_BOX = [
    0x3, 0xf, 0xe, 0x8,
    0x0, 0x4, 0xa, 0x1,
    0x2, 0xd, 0xb, 0x7,
    0x5, 0x9, 0x6, 0xc
]

def s_box_substitution(input_block):
    output_block = 0
    for i in range(0, 8):
        nibble = (input_block >> (i * 4)) & 0xF
        substituted = S_BOX[nibble]
        output_block |= (substituted << (i * 4))
    return output_block

def f_function(right_half, subkey):
    right_half = right_half & 0xFFFFFFFF
    subkey = subkey & 0xFFFFFFFF

    xor_result = right_half ^ subkey
    f_result = s_box_substitution(xor_result)
    
    return f_result

def feistel_encrypt(plain_text, subkeys):
    plain_text = plain_text & 0xFFFFFFFFFFFFFFFF

    left_half = (plain_text >> 32) & 0xFFFFFFFF
    right_half = plain_text & 0xFFFFFFFF


    for i in range(16):
        next_left = right_half
        next_right = left_half ^ f_function(right_half, subkeys[i])
        left_half = next_left
        right_half = next_right

    cipher_text = (left_half << 32) | right_half
    return cipher_text

def generate_subkeys():
    return [random.getrandbits(32) for _ in range(16)]

plain_text = 0x0123456789ABCDEF  # 64-bit input
subkeys = generate_subkeys()
cipher_text = feistel_encrypt(plain_text, subkeys)

print(f"Plaintext: 0x{plain_text:016X}")
print(f"Ciphertext: 0x{cipher_text:016X}")
