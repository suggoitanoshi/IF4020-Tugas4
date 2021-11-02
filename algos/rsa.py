from typing import Tuple
import sympy
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
  # Memecah pesan menjadi beberapa blok sesuai n (RSA) atau p (ElGamal)
  maxnum = 255
  lennum = len(str(maxnum))
  lenn = len(str(n))
  mult = lenn//lennum
  temp = maxnum
  for i in range(1, mult):
    temp = temp * (10**lennum) + maxnum
  if lenn % lennum == 0:
    if n <= temp:
      temp = temp // 1000
      mult = mult - 1
  msg = [x for x in message]
  print('original:', msg)
  msggroup = []
  # Kelompokkan msg sesuai menjadi mult msg dalam 1 kelompok
  if mult > 1:
    i = 0
    while i<len(msg):
      grouped = ''
      if i+mult < len(msg):
        for j in range(i,i+mult):
          grouped = grouped + str(msg[j]).zfill(lennum)
      else:
        for j in range(i,len(msg)):
          grouped = grouped + str(msg[j]).zfill(lennum)
        grouped = grouped.zfill(lennum*mult)
      i = i + mult
      msggroup.append(int(grouped))
    return msggroup
  else:
    return msg

def generatePrime(b):
  # Pembangkit angka prima sebesar b bits
  rand = sympy.randprime(2**(b-1), 2**(b)-1)
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
# print(divideMessage(str.encode("tehe contoh pesan"), 300000))