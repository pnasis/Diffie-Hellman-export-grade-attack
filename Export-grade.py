#! /usr/bin/env python3
import pwn
import json
import hashlib
from sage.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# Check if a message is PKCS7 padded.
def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


# Decrypt the flag using AES encryption and PKCS7 padding.
def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')


# Solve the discrete logarithm problem in a finite field.
def solve_discrete_log(p, g, A, B):
    F = GF(p)
    g, A = F(g), F(A)
    a = discrete_log(A,g)
    return pow(B, int(a), p)


def main():
    # Establish the connection with the server.
    remote = pwn.remote("socket.cryptohack.org", 13379)

    # Intercept and alter the supported protocol versions.
    remote.recvuntil("Intercepted from Alice: ".encode())
    intercepted_from_alice = json.loads(remote.recvline())
    intercepted_from_alice['supported'] = ["DH64"]
    remote.recvuntil("Send to Bob: ".encode())
    remote.sendline(json.dumps(intercepted_from_alice).encode('utf-8'))

    # The request is simply forwarded to Bob.
    remote.recvuntil("Intercepted from Bob: ".encode())
    intercepted_from_bob = json.loads(remote.recvline())
    remote.recvuntil("Send to Alice: ".encode())
    remote.sendline(json.dumps(intercepted_from_bob).encode('utf-8'))

    # Intercept Diffie-Hellman parameters.
    remote.recvuntil("Intercepted from Alice: ".encode())
    intercepted_from_alice = json.loads(remote.recvline())
    p = int(intercepted_from_alice["p"], 16)
    g = int(intercepted_from_alice["g"], 16)
    A = int(intercepted_from_alice["A"], 16)

    # Intercept public keys.
    remote.recvuntil("Intercepted from Bob: ".encode())
    intercepted_from_bob = json.loads(remote.recvline())
    B = int(intercepted_from_bob["B"], 16)
    remote.recvuntil("Intercepted from Alice: ".encode())
    alice_ciphertext = json.loads(remote.recvline())

    # Solve the discrete log problem.
    shared_secret = solve_discrete_log(p, g, A, B)

    # Decrypt the flag.
    flag = decrypt_flag(shared_secret, alice_ciphertext["iv"], alice_ciphertext["encrypted_flag"])
    pwn.log.info(flag)

if __name__ == "__main__":
    main()