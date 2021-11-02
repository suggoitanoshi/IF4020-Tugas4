from typing import Tuple
import sympy
import random
import sys
import math


def genkey(bitsize = 32) -> Tuple[dict[str, int], dict[str, int]]:
  """Generator kunci untuk RSA"""
  # size = ukuran p dan q dalam bits
  # Ukuran n adalah 2 * size
  size = bitsize

  # Bangkitkan p dan q
  p = generatePrime(size)
  q = generatePrime(size)

  while p == q:
    q = generatePrime(size)

  n = p*q
  phi = (p-1)*(q-1)
  e = randCoprime(phi)
  d = pow(e, -1, phi)

  # Buat kunci publik dan privat
  # Kunci publik = (e, n)
  # Kunci privat = (d, n)

  return ({'e': e, 'n': n}, {'d': d, 'n': n})

def encodekey(key: Tuple[dict[str, int], dict[str, int]]) -> Tuple[dict[str, str], dict[str, str]]:
  pubkey, privkey = key
  pubkey['e'] = hex(pubkey['e'])
  pubkey['n'] = hex(pubkey['n'])
  privkey['d'] = hex(privkey['d'])
  privkey['n'] = hex(privkey['n'])
  return (pubkey, privkey)

def decodekey(key: dict[str, str]) -> dict[str,int]:
  decoded = {}
  for k in key.keys():
    decoded[k] = int(key[k], 16)
  return decoded 

def encrypt(message: bytes, key: dict[str, int]) -> bytes:
  """Fungsi enkripsi untuk RSA"""
  e = key['e']
  n = key['n']
  bsize = countBlock(n)
  msg = divideMessage(message, n)
  c = bytearray()
  for i in range(0,len(msg)):
    a = pow(msg[i],e,n)
    c.extend(a.to_bytes(bsize, byteorder=sys.byteorder, signed=False))
  return c

def decrypt(message: bytes, key: dict[str,int]) -> bytes:
  """Fungsi dekripsi untuk RSA"""
  d = key['d']
  n = key['n']
  m = []
  plain = bytearray()
  bsize = countBlock(n)
  for i in range(0, len(message), bsize):
    a = int.from_bytes(message[i:i+bsize], byteorder=sys.byteorder, signed=False)
    m.append(pow(a,d,n))

  return blockToMessage(m,n)

def countBlock(n):
  res = math.ceil(math.log2(n)/8)

  return res

def blockToMessage(blockarray, n):
  # Mengubah pesan berupa blok angka kembali menjadi huruf
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

  msg = []
  # Pecah pesan mencadi 1 byte
  for i in range(0,len(blockarray)):
    temp = str(blockarray[i]).zfill(mult*lennum)
    temparr = [temp[j:j+lennum] for j in range(0, len(temp), lennum)]
    for k in temparr:
      if k!= '000':
       msg.append(int(k).to_bytes(1,'big'))
  return b''.join(msg)

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

def egcd(a,b):
  if a == 0:
    return b, 0, 1
  gcd, x, y = egcd(b%a, a)
  return gcd, (y-(b//a)*x), x

def randCoprime(x):
  # Pembangkit angka acak yang relatif prima dengan x
  # Syarat bilangan relatif prima adalah GCD == 1
  rand = random.randint(3, 65537)
  while gcd(rand,x) != 1:
    rand = random.randint(3, 65537)

  return rand

# Testing
# genkey()
# divided = divideMessage(str.encode("tehe contoh pesan"), 300000)
# print(divided)
# returned = blockToMessage(divided, 300000)
# print(returned.decode('utf-8'))
