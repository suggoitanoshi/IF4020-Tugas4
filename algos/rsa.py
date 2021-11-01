from typing import Tuple
import random

def genkey() -> Tuple[bytes, bytes]:
  """Generator kunci untuk RSA"""
  # size = ukuran p dan q dalam bits
  # Ukuran n adalah 2 * size
  size = 32

  # Bangkitkan p dan q
  p = generatePrime(size)
  print("p   =",p)
  q = generatePrime(size)
  print("q   =",q)

  while p == q:
    q = generatePrime(size)
    print("q == p, generating q...")
    print("q   =",q)

  n = p*q
  print("n   =",n)

  phi = (p-1)*(q-1)
  print("phi =",phi)

  e = randCoprime(phi)
  print("e   =",e)

  d = calcRSADecryptKey(phi, e)
  print("d   =",d)

  # Buat kunci publik dan privat
  # Kunci publik = (e, n)
  # Kunci privat = (d, n)
  publickey = (e, n)
  privatekey = (d, n)

  return publickey, privatekey

def encrypt(message: bytes, pubkey: bytes) -> bytes:
  """Fungsi enkripsi untuk RSA"""
  e = pubkey[0]
  n = pubkey[1]
  msg = divideMessage(message, n)

def decrypt(message: bytes, prikey: bytes) -> bytes:
  """Fungsi dekripsi untuk RSA"""
  d = prikey[0]
  n = prikey[1]
  msg = divideMessage(message, n)

def divideMessage(message, n):
  # Memecah pesan menjadi beberapa blok sesuai n
  pass

def isPrime(x):
  # Mengembalikan True jika x prima
  if x % 2 == 0:
    return False

  i = 3
  while i*i <= x:
    if x%i == 0:
      return False
    i = i + 2
  
  return True

def generatePrime(b):
  # Pembangkit angka prima sebesar b bits
  rand = random.randint(2**(b-1), 2**(b)-1)
  while isPrime(rand) == False:
    rand = random.randint(2**(b-1), 2**(b)-1)
  return rand

def gcd(a,b):
  if b == 0:
    return a
  else:
    return gcd(b, a%b)

def randCoprime(x):
  # Pembangkit angka acak yang relatif prima dengan x
  # Syarat bilangan relatif prima adalah GCD == 1
  rand = random.randint(3, 65537)
  while gcd(rand,x) != 1:
    rand = random.randint(3, 65537)

  return rand

def calcRSADecryptKey(phi, e):
  # Menghitung nilai d berdasarkan n dan e
  d = 1 + phi
  while d%e!=0:
    d = d + phi

  return d

# Testing
# genkey()