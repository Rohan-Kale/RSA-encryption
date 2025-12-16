from typing import Tuple
import random
import math

# Type defs
Key = Tuple[int, int]

MIN_ASCII = 32
MAX_ASCII = 128
BASE = MAX_ASCII - MIN_ASCII

def gcd(a: int, b: int) -> int:
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a%b
    return a

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, y, x = extended_gcd(b % a, a)
    x = x - (b//a) * y
    return g, x, y

def inverse_mod(e: int, phi: int) -> int:
    _, x, _ = extended_gcd(e, phi)

    return x % phi

def manual_pow(base: int, ex: int, mod: int) -> int:
    res = 1
    base %= mod
    while ex > 0:
        if ex % 2 ==1:
            res = (res * base) % mod
        base = (base * base) % mod
        ex //= 2
    return res
    

def is_prime(num: int):
    if num <= 1:
        return False
    if num <= 3:
        return True
    if num % 2 == 0:
        return False
    
    count = 5
    for _ in range(count):
        rand_num = random.randrange(2, num-2)
        if manual_pow(rand_num, num-1, num) != 1:
            return False
    return True
    
    

def generate_prime(n: int) -> int:
    '''
    Description: Generate an n-bit prime number
    Args: n (No. of bits)
    Returns: prime number
    
    NOTE: This needs to be sufficiently fast or you may not get
    any credit even if you correctly return a prime number.
    '''
    if not isinstance(n, int) or n < 2:
        raise ValueError("n must be an integer >= 2")
    low = 1 << (n-1) # sets very first digit to 1 and all others are 0
    high = (1 << n) - 1 # sets all digits in binary to 1
    while True:
        prime = random.randrange(low, high, 2) 
        prime |= 1
        prime |= low
        if is_prime(prime):
            return prime
        
def generate_keypair(p: int, q: int) -> Tuple[Key, Key]:
    '''
    Description: Generates the public and private key pair
    if p and q are distinct primes. Otherwise, raise a value error
    
    Args: p, q (input integers)

    Returns: Keypair in the form of (Pub Key, Private Key)
    PubKey = (n,e) and Private Key = (n,d)
    '''
    if not isinstance(p, int) or not isinstance(q, int):
        raise ValueError("p and q have to be integers")
    if not is_prime(p) or not is_prime(q):
        raise ValueError("p and q have to be prime numbers")
    if p == q:
        raise ValueError("p and q have to be distinct prime values")
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 3
    while gcd(e, phi) != 1:
        e += 2
    
    d = inverse_mod(e, phi)
    return ((n, e), (n, d))


def rsa_encrypt(m: str, pub_key: Key, blocksize: int) -> str:
    '''
    Description: Encrypts the message with the given public
    key using the RSA algorithm.

    Args: m (input string)

    Returns: c (encrypted cipher)
    NOTE: You CANNOT use the built-in pow function (or any similar function)
    here.
    '''
    n, e = pub_key

    padding_needed = (blocksize - len(m) % blocksize) % blocksize
    m_padded = m + ' ' * padding_needed

    encrypted = []

    for i in range(0, len(m_padded), blocksize):
        chunk = m_padded[i:i + blocksize]
        chunk_num = chunk_to_num(chunk)

        cipher = manual_pow(chunk_num, e, n)
        encrypted.append(cipher)

    #print('ENCRYPTED NUM', encrypted)
    result = ""
    for cipher in encrypted:
        result += num_to_chunk(cipher, blocksize)
    return result


def rsa_decrypt(c: str, priv_key: Key, blocksize: int) -> int:
    '''
    Description: Decrypts the ciphertext using the private key
    according to RSA algorithm

    Args: c (encrypted cipher string)

    Returns: m (decrypted message, a string)
    NOTE: You CANNOT use the built-in pow function (or any similar function)
    here.
    '''
    n, d = priv_key
    text = ''
    
    if isinstance(c, str):
        import math
        c_size = math.ceil(math.log(n, BASE))
        
        encrypted = []
        for i in range(0, len(c), c_size): 
            chunk = c[i:i + c_size]        
            while len(chunk) < c_size:       
                chunk += ' '
            cipher_num = chunk_to_num(chunk)
            encrypted.append(cipher_num)
    else:
        encrypted = c
    
    for cipher in encrypted:
        chunk_num = manual_pow(cipher, d, n)
        chunk = num_to_chunk(chunk_num, blocksize) 
        text += chunk
    
    #print("TEXT", text)
    return text

def chunk_to_num( chunk ):
    '''
    Description: Convert chunk (substring) to a unique number mod n^k
    n is the common modulus, k is length of chunk.

    Args: chunk (a substring of some messages)

    Returns: r (some integer)
    NOTE: You CANNOT use any built-in function to implement base conversion. 
    '''
    number = 0
    for i, c in enumerate(chunk):
        number += (ord(c) -MIN_ASCII) * (BASE ** i)  
    
    #print("RETURNED NUMBER", number)
    return number

def num_to_chunk( num, chunksize ):
    '''
    Description: Convert a number back to a chunk using a given 
    chunk size

    Args: num (integer), chunksize (integer)

    Returns: chunk (some substring)
    NOTE: You CANNOT use any built-in function to implement base conversion. 
    '''
    res = []
    temp_num = num
    while temp_num > 0:
        val = temp_num % BASE
        res.append(chr(val + MIN_ASCII))
        temp_num //= BASE
    
    chunk = "".join(res)
    while len(chunk) < chunksize:
        chunk += " "
    
    #print("RETURNED CHUNK", chunk)
    return chunk
