# digital-signature-using-rsa
Implementation of digital signature using RSA

Requirements
------------
1. Crypto - https://pypi.python.org/pypi/pycrypto
2. gmpy2 - https://pypi.python.org/pypi/gmpy2

Encryption	
----------
1.	We take the user input for message
2.	First, we generate two random prime numbers p and q of 512 bit length.
3.	We calculate n = p * q
4.	We calculate Φ(n) = p-1 * q-1
5.	We calculate e, such that gcd(e, Φ(n)) = 1
6.	We calculate d, such that e * d = 1 mod Φ(n)
7.	We calculate the message digest using SHA-224, M
8.	We encrypt the message digest using senders public key CT = M^d mod n.
9.	We send the M+S to receiver and (e, n) is made known to public.

Decryption
----------
1.	We first separate the message from encrypted message digest
2.	We then decrypt the message digest using sender public key S'= M^e mod n.
3.	We then calculate the message digest of the message using SHA-224, M'
4.	If M' = S', then the sender is indeed the real sender and the message is not been tampered with.
