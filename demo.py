"""
A basic demo about how the XOR Cipher (Vernam Cipher) can be implemented for two parties.
"""

import random
import textwrap
# from sympy.ntheory import primitive_root


def ascii_to_bin(ascii_str):
    block_list = [bin(ord(ch))[2:] for ch in ascii_str]
    bin_str = ''.join(str(block).zfill(7) for block in block_list)
    return bin_str


def bin_to_ascii(bin_str):
    block_list = textwrap.wrap(bin_str, 7)
    ascii_str = ''.join(chr(int(block, 2)) for block in block_list)
    return ascii_str


def DiffieHellman(p, g_pow_k, my_secret_number):
    return pow(g_pow_k, my_secret_number, p)


def keystream(loc):
    random.seed(loc[0])
    bit = random.randint(0, 1)
    loc[0] += 1
    return bit


def xor_cipher(text, key, decrypt=False):
    # The decision was made to keep the ciphertext as binary because if it's cast to ASCII then we
    # get some non-printable ASCII characters. Plaintext returned as ASCII

    if decrypt:
        bin_plaintext = ''.join(str(bit ^ key()) for bit in map(int, text))
        ascii_plaintext = bin_to_ascii(bin_plaintext)
        return ascii_plaintext
    else:
        bin_plaintext = ascii_to_bin(text)
        bin_ciphertext = ''.join(str(bit ^ key()) for bit in map(int, bin_plaintext))
        return bin_ciphertext

    # Old function:
    # block_list = textwrap.wrap(bin_ciphertext, 7)
    # ciphertext = ''.join(chr(int(block, 2)) for block in block_list)
    # return ciphertext


def main():
    # [PUBLIC] Choose some large prime p; g is the result of primitive_root(p)
    p = 23055786698571145695688900785540069093045313423195016857145109648326181786526117247237971391007655833311814973076717911
    g = 6

    # [PRIVATE] Each party randomly chooses a number between 2 and p-1 (inclusive)
    my_secret_number = random.randint(2, p-1)
    your_secret_number = random.randint(2, p-1)

    # [PUBLIC] The result of (g ** your_secret_number) % p
    g_pow_yours = pow(g, your_secret_number, p)

    # [PRIVATE] the result of DiffieHellman(p, g_pow_yours, my_secret_number)
    shared_key = DiffieHellman(p, g_pow_yours, my_secret_number)

    # Starting point for keystream(); must be lists so they are changed in memory across multiple runs of keystream
    MY_LOC = [shared_key]
    YOUR_LOC = [shared_key]

    plaintext = input('Enter a message to encrypt (ASCII only):\n')
    ciphertext = xor_cipher(plaintext, lambda: keystream(MY_LOC))

    print(f'\nBinary ciphertext (encrypted with MY_LOC):\n{ciphertext}')

    print('\n' + '_' * 100)
    input('[press ENTER to decrypt]')

    decrypted_plaintext = xor_cipher(ciphertext, lambda: keystream(YOUR_LOC), decrypt=True)
    print(f'\nDecrypted plaintext (decrypted with YOUR_LOC):\n{decrypted_plaintext}')

    print()
    if plaintext == decrypted_plaintext:
        print('SUCCESS (original = decrypted)')
    else:
        print('FAIL (original != decrypted)')

    print('\n' + '_' * 100)
    input('[press ENTER to see cryptographic info]')

    print()
    # print('-'*100)
    print('Parameters for Diffie-Hellman key exchange:')
    print()
    print('\tprime modulus:')
    print(f'\tp = {p}')
    print()
    print('\tprimitive root:')
    print(f'\tg = {g}')
    print()
    print("\t1st party's secret number (randomly selected):")
    print(f'\ta = {my_secret_number}')
    print()
    print("\t2nd party's secret number (randomly selected):")
    print(f'\tb = {your_secret_number}')
    print()
    print('\tshared key:')
    print(f'\tg^ab (mod p) = {shared_key}')


if __name__ == '__main__':
    main()
