# Author - Santosh Panna
# Version - 0.0.2
# Descriptopn - Implementation of Digital Signature using RSA

import Crypto.Util.number as CryNum
import random
import gmpy2
import sys
import hashlib

#genPrime returns a prime number for a fixed bit size
def genPrime(size):
	return (CryNum.getPrime(size))

#genN return n = p*q
def genN(p,q):
	return (p*q)

#gcd return the greatest common devisor of the two nos using Euclidean Algorithm
def gcd(a,b):
	a = abs(a)
	b = abs(b)

	#if a<b then interchange the value of a and b
	if a<b:
		a, b = b, a

	#replace a = b and b = a%b
	while b != 0:
		a, b = b, a%b

	#return the gcd
	return a

#getRandE return the value of e such that e is coprime of O(n)
def genRandE(phin):
	e=65537

	g = gcd(e, phin)
	#checking if e and )(n) is coprime
	while g != 1:
		e = random.randrange(1, phin)
		g = gcd(e, phin)

	return e

#genPrivKey return the private key d such that d = (k*O(n) + 1)
def genPrivKey(phin, e):
	k = genRand(512)
	#d = (k*O(n) + 1) / e for some integer k
	return ((((k*phin) +1))/e)

#encrypt encrypts the message digest (sha224) and then stores the private key and public key pair into a file and also the message and the encrypted digest
def encrypt():
	#take user message
	print("Enter the message to encrypt")
	msg = raw_input()

	# p and q large prime numbers between length 512 and 2048
	p, q = genPrime(512), genPrime(512)
	#if p = q then genrate another p and q
	while p == q:
		p, q = genPrime(512), genPrime(512)

	#computing n = p*q
	n = genN(p,q)

	#computing O(n) = (p-1)(p-1)
	phin = genN(p-1, q-1)

	#compute e, 1<e<O(n); such that gcd(e,O(n)) = 1
	e = genRandE(phin)

	#computing d, 1<d<O(n); such that e*d = 1 mod O(n) or d = multiplicativeinverse(e,phin)
	d = gmpy2.invert(e, phin)

	#Public Key = (e,n)
	#Private Key = d

	#calculating the hash of message using sha224
	digest = hashlib.sha224(msg).hexdigest()

	#converting the digest to its ascii value
	m = ''
	for i in digest:
		m = m+str(ord(i))

	#encypting the digest using RSA algorithm CT = M^d mod n
	encDigest = pow(int(m),d,n)

	'''
	print("p = "+str(p)+"\nq = "+str(q)+"\nN = "+str(n)+"\nO(n) = "+str(phin)+"\ne = "+str(e)+"\nd = "+str(d)+"\nDigest = "+str(digest)+"\nEncrypted Digest = "+str(encDigest))
	'''
	
	#writing message+digest to a file
	with open('transfer.txt', 'w') as file:
		file.write(msg+str(encDigest))
		file.close()

	#writing public key to a file
	with open('publicKey.txt', 'w') as file:
		file.write(str(e).strip()+"\n"+str(n).strip())
		file.close()

	#writing private key to a file
	with open('privateKey.txt', 'w') as file:
		file.write(str(d).strip())
		file.close()

#decrypt opens the file seperates message and digest, decrypt the digest using the public key and compares it to caluclated hash of the message
def decrypt():
	#openign the message file
	msg = open('transfer.txt').read()

	#calulating the length of message + digest
	l = len(msg)

	#calculating the length of message
	start = 0
	for i in msg:
		#assumption is that the sender will not send a number in the message
		start += 1
		if i.isdigit() == True:
			break

	#getting the lenght of encrypted digest
	start = (l - int(start)+1) * -1
	
	#sperating digest from message
	digest = msg[start:l]
	msg = msg.replace(digest, '')

	#getting the public key e and n
	pk = open('publicKey.txt').read()
	pk = pk.split("\n")
	e = pk[0]
	n = pk[1]

	o = ''
	
	#caching the converted int of e and n
	e = int(e)
	n = int(n)
	
	#decrypting the encrypted digest using RSA algorithm PT = M^e mod n
	o = str(pow(int(digest), e, n))

	#calculating the hash of the message using sha224
	msg = hashlib.sha224(msg).hexdigest()

	#converting the message digest to its ascii value
	m = ''
	for i in msg:
		m = m+str(ord(i))

	'''
	print("Recieved Digest = "+str(digest)+"\nRecieved Message = "+str(msg)+"\ne = "+str(e)+"\nn = "+str(n)+"\nCaculated hash = "+str(m))
	'''
	
	#if decypted digest == calculated hash then the sender is verified else message has been tampered with
	if m == o:
		print("Sender Verified.")
	else:
		print("Not able to verify the sender and/or message has been tampered.")


if __name__ == '__main__':
	#increasing the memory allocation to accomodate calculations and storage of very large numbers
	sys.maxsize = sys.maxsize*sys.maxsize

	#Asking the user for choice to encrypt or decrypt the data
	print("Enter e or encrypt to encrypt and d or decrypt to decrypt")
	mode = raw_input()
	if mode == 'e' or mode == 'encrypt' or mode == 1:
		encrypt()
	elif mode == 'd' or mode == 'decrypt' or mode == 0:
		decrypt()
	else:
		print("Wrong choice")