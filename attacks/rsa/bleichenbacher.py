import logging
import os
import sys
import secrets

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared import ceil
from shared import floor


def _insert(M, a, b):
    """Inserts a new interval (a, b) into a list of intervals M.
    Parameters:
        - M (list): List of intervals to insert into.
        - a (int): Start of the new interval.
        - b (int): End of the new interval.
    Returns:
        - None: Modifies the list M in-place.
    Processing Logic:
        - Checks if the new interval overlaps with any existing intervals in M.
        - If it does, merges the intervals and updates M.
        - If it doesn't, appends the new interval to M."""
    
    for i, (a_, b_) in enumerate(M):
        if a_ <= b and a <= b_:
            a = min(a, a_)
            b = max(b, b_)
            M[i] = (a, b)
            return

    M.append((a, b))
    return


# Step 1.
def _step_1(padding_oracle, n, e, c):
    """Returns:
        - s0 (int): The random number generated for the encryption.
        - c0 (int): The encrypted message after padding.
    Parameters:
        - padding_oracle (function): A function that checks if the padding is correct.
        - n (int): The modulus used for encryption.
        - e (int): The public exponent used for encryption.
        - c (int): The encrypted message to be decrypted.
    Processing Logic:
        - Generate a random number s0.
        - Multiply c by s0^e mod n.
        - Repeat until padding is correct.
        - Return the random number and encrypted message."""
    
    s0 = 1
    c0 = c
    while not padding_oracle(c0):
        s0 = secrets.SystemRandom().randrange(2, n)
        c0 = (c * pow(s0, e, n)) % n

    return s0, c0


# Step 2.a.
def _step_2a(padding_oracle, n, e, c0, B):
    """"Calculate the smallest value of s that satisfies the padding oracle condition for the given parameters."
    Parameters:
        - padding_oracle (function): A function that checks if a given ciphertext satisfies the padding oracle condition.
        - n (int): The modulus used in the RSA encryption.
        - e (int): The public exponent used in the RSA encryption.
        - c0 (int): The ciphertext to be decrypted.
        - B (int): The block size used in the RSA encryption.
    Returns:
        - s (int): The smallest value of s that satisfies the padding oracle condition.
    Processing Logic:
        - Calculate the smallest value of s that satisfies the padding oracle condition.
        - Use ceil function to round up the result of n divided by 3 times B.
        - Increment s by 1 until the padding oracle condition is satisfied.
        - Return the final value of s.
    Example:
        s = _step_2a(padding_oracle, n, e, c0, B)
        print(s)
        # Output: 123456789"""
    
    s = ceil(n, 3 * B)
    while not padding_oracle((c0 * pow(s, e, n)) % n):
        s += 1

    return s


# Step 2.b.
def _step_2b(padding_oracle, n, e, c0, s):
    """Returns the smallest s value that satisfies the padding oracle for a given ciphertext c0 and public key (n, e).
    Parameters:
        - padding_oracle (function): A function that checks if a given ciphertext is valid.
        - n (int): The modulus of the public key.
        - e (int): The public exponent of the public key.
        - c0 (int): The ciphertext to be decrypted.
        - s (int): The starting value for s.
    Returns:
        - s (int): The smallest s value that satisfies the padding oracle.
    Processing Logic:
        - Increment s until the padding oracle returns True.
        - Return the final value of s.
        - s is incremented by 1 each time.
        - The padding oracle is used to check if the ciphertext is valid."""
    
    s += 1
    while not padding_oracle((c0 * pow(s, e, n)) % n):
        s += 1

    return s


# Step 2.c.
def _step_2c(padding_oracle, n, e, c0, B, s, a, b):
    """"Calculates the correct value of s for a given padding oracle, n, e, c0, B, s, a, and b.
    Parameters:
        - padding_oracle (function): A function that checks if a given ciphertext is correctly padded.
        - n (int): The modulus used in the RSA encryption.
        - e (int): The public exponent used in the RSA encryption.
        - c0 (int): The ciphertext to be decrypted.
        - B (int): The bound used in the Bleichenbacher attack.
        - s (int): The initial value of s used in the attack.
        - a (int): The lower bound for the range of s values to be checked.
        - b (int): The upper bound for the range of s values to be checked.
    Returns:
        - s (int): The correct value of s for the given parameters.
    Processing Logic:
        - Calculates the value of r based on the given parameters.
        - Loops through a range of s values between the calculated left and right bounds.
        - Checks if the ciphertext is correctly padded using the padding_oracle function.
        - If the ciphertext is correctly padded, returns the current value of s.
        - If no correctly padded ciphertext is found, increments r and repeats the process.
    """"
    
    r = ceil(2 * (b * s - 2 * B), n)
    while True:
        left = ceil(2 * B + r * n, b)
        right = floor(3 * B + r * n, a)
        for s in range(left, right + 1):
            if padding_oracle((c0 * pow(s, e, n)) % n):
                return s

        r += 1


# Step 3.
def _step_3(n, B, s, M):
    """Calculates the range of values for a and b based on the given parameters and inserts them into a list.
    Parameters:
        - n (int): The value of n.
        - B (int): The value of B.
        - s (int): The value of s.
        - M (list): A list of tuples containing values for a and b.
    Returns:
        - M_ (list): A list of tuples containing updated values for a and b.
    Processing Logic:
        - Calculates the left and right bounds for a and b based on the given parameters.
        - Inserts the updated values for a and b into a new list.
        - Returns the updated list."""
    
    M_ = []
    for (a, b) in M:
        left = ceil(a * s - 3 * B + 1, n)
        right = floor(b * s - 2 * B, n)
        for r in range(left, right + 1):
            a_ = max(a, ceil(2 * B + r * n, s))
            b_ = min(b, floor(3 * B - 1 + r * n, s))
            _insert(M_, a_, b_)

    return M_


def attack(padding_oracle, n, e, c):
    """
    Recovers the plaintext using Bleichenbacher's attack.
    More information: Bleichenbacher D., "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1"
    :param padding_oracle: the padding oracle taking integers, returns True if the PKCS #1 v1.5 padding is correct, False otherwise
    :param n: the modulus
    :param e: the public exponent
    :param c: the ciphertext (integer)
    :return: the plaintext (integer)
    """
    k = ceil(n.bit_length(), 8)
    B = 2 ** (8 * (k - 2))
    logging.info("Executing step 1...")
    s0, c0 = _step_1(padding_oracle, n, e, c)
    M = [(2 * B, 3 * B - 1)]
    logging.info("Executing step 2.a...")
    s = _step_2a(padding_oracle, n, e, c0, B)
    M = _step_3(n, B, s, M)
    logging.info("Starting while loop...")
    while True:
        if len(M) > 1:
            s = _step_2b(padding_oracle, n, e, c0, s)
        else:
            (a, b) = M[0]
            if a == b:
                m = (a * pow(s0, -1, n)) % n
                return m
            s = _step_2c(padding_oracle, n, e, c0, B, s, a, b)
        M = _step_3(n, B, s, M)
