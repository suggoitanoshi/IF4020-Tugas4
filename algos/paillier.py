from typing import Tuple
from secrets import randbelow
import sys

from sympy.functions.elementary.complexes import sign

from algos.rsa import generatePrime

def __L(x: int, n: int) -> int:
  return (x-1)//n

def __extended_euclid(a: int, b: int) -> Tuple[int, int, int]:
  if a == 0:
    return (b, 0, 1)
  else:
    gcd, x, y = __extended_euclid(b % a, a)
    return (gcd, y - (b//a)*x, x)

def __modinv(a: int, m: int) -> int:
  gcd, x, _ = __extended_euclid(a, m)
  if gcd != 1:
    raise Exception('Modular inverse failed')
  else:
    return x % m

def decodekey(key: dict[str, str]) -> dict[str,int]:
  decoded = {}
  for k in key.keys():
    decoded[k] = int(key[k], 16)
  return decoded 

def encodekey(key: Tuple[dict[str, int], dict[str, int]]) -> Tuple[dict[str, str], dict[str, str]]:
  pubkey, privkey = key
  pubkey['g'] = hex(pubkey['g'])
  pubkey['n'] = hex(pubkey['n'])
  privkey['l'] = hex(privkey['l'])
  privkey['mu'] = hex(privkey['mu'])
  privkey['n'] = hex(privkey['n'])
  return (pubkey, privkey)

def genkey() -> Tuple[dict[str, int], dict[str, int]]:
  """Fungsi untuk membuat kunci publik dan privat Paillier
  Return berupa tuple (pubkey, privkey)
  """
  bits = 32
  p = generatePrime(bits)
  q = generatePrime(bits)
  n = p*q
  while __extended_euclid(n, (p-1)*(q-1))[0] != 1:
    q = generatePrime(bits)
    n = p*q
  l = (p-1)*(q-1)//__extended_euclid(p-1,q-1)[0]
  g = randbelow(n**2)
  mu = __modinv(__L(pow(g, l, n**2), n), n)
  return encodekey(({'g': g, 'n':n}, {'l':l, 'mu':mu, 'n':n}))

__blocking = 8

def encrypt(message: bytearray, key: dict[str, int]) -> bytes:
  """Fungsi untuk mengenkripsi pesan dengan Algoritma Paillier"""
  c = bytearray()
  n = key['n']
  g = key['g']
  nsq = n**2
  blocking = __blocking #bytes
  for i in range(0, len(message), blocking): # work in blocking message length
    if i+blocking>=len(message):
      m = int.from_bytes(message[i:], byteorder=sys.byteorder)
    else:
      m = int.from_bytes(message[i:i+blocking], byteorder=sys.byteorder, signed=False)
    r = randbelow(key['n'])
    while __extended_euclid(r, n)[0] != 1:
      r = randbelow(key['n'])
    c.extend((
      (pow(g, m, nsq) * pow(r, n, nsq))
      % (nsq)).to_bytes(16, byteorder=sys.byteorder, signed=False)
      )
  return c

def decrypt(message: bytearray, key: dict[str, int]) -> bytes:
  """Fungsi untuk mencoba mendekripsi pesan dengan Algoritma Paillier"""
  l = key['l']
  mu = key['mu']
  n = key['n']
  p = bytearray()
  for i in range(0, len(message), 16):
    if len(message) < 16:
      m = int.from_bytes(message, byteorder=sys.byteorder, signed=False)
    else:
      m = int.from_bytes(message[i:i+16], byteorder=sys.byteorder, signed=False)
    b = __L(pow(m, l, n**2), n)*mu % n
    p.extend(b.to_bytes((b.bit_length()+7)//8, byteorder=sys.byteorder, signed=False))
  return p