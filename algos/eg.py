from typing import Tuple
import sys

from algos.rsa import generatePrime
from secrets import randbelow

def genkey() -> Tuple[dict[str, int], dict[str, int]]:
  """Fungsi pembangkit kunci ElGamal
  Return (pubkey, privkey)
  """
  p = generatePrime(32)
  g = randbelow(p)
  x = randbelow(p-2)+1
  y = pow(g, x, p)
  return ({'y': y, 'g': g, 'p': p}, {'x': x, 'p': p})

def encodekey(key: Tuple[dict[str, int], dict[str, int]]) -> Tuple[dict[str, str], dict[str, str]]:
  pubkey, privkey = key
  pubkey['y'] = hex(pubkey['y'])
  pubkey['g'] = hex(pubkey['g'])
  pubkey['p'] = hex(pubkey['p'])
  privkey['x'] = hex(privkey['x'])
  privkey['p'] = hex(privkey['p'])
  return (pubkey, privkey)

def decodekey(key: dict[str, str]) -> dict[str,int]:
  decoded = {}
  for k in key.keys():
    decoded[k] = int(key[k], 16)
  return decoded 

__blocksize = 4

def encrypt(message: bytes, key: dict[str, int]) -> bytes:
  p = key['p']
  g = key['g']
  y = key['y']
  c = bytearray()
  for i in range(0, len(message), __blocksize):
    if i+__blocksize >= len(message):
      m = int.from_bytes(message[i:], byteorder=sys.byteorder, signed=False)
    else:
      m = int.from_bytes(message[i:i+__blocksize], byteorder=sys.byteorder, signed=False)
    k = randbelow(p-2)+1
    a = pow(g, k, p)
    b = pow(y, k, p) * (m % p) % p
    c.extend(a.to_bytes(__blocksize, byteorder=sys.byteorder, signed=False))
    c.extend(b.to_bytes(__blocksize, byteorder=sys.byteorder, signed=False))
  return c

def decrypt(message: bytes, key: dict[str,int]) -> bytes:
  x = key['x']
  p = key['p']
  plain = bytearray()
  for i in range(0, len(message), 8):
    a = int.from_bytes(message[i:i+4], byteorder=sys.byteorder, signed=False)
    b = int.from_bytes(message[i+4:i+8], byteorder=sys.byteorder, signed=False)
    axinv = pow(a, p-1-x, p)
    m = b*axinv%p
    plain.extend(m.to_bytes((m.bit_length()+7)//8, byteorder=sys.byteorder, signed=False))
  return plain