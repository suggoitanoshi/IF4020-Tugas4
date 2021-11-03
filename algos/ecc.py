from typing import Tuple
import random
import sys
import tinyec.ec as ec
import tinyec.registry as reg

def genkey(name = "secp192r1") -> Tuple[dict[str, int], dict[str, int]]:
  """Fungsi pembangkit kunci ECC
     y^2 = x^3 + ax + b mod p"""
  c = reg.get_curve(name) # using a standard curve
  privkey = random.randint(1,c.field.p)
  pubkey = privkey * c.g
  return ({'x': pubkey.x, 'y':pubkey.y, 'curvename':c.name}, {'priv' : privkey, 'curvename':c.name})

def byteToPoint(m, c):
  # Mengkonversi m = 0-255 menjadi titik pada kurva
  return m * c.g

def pointToByte(point, c):
    # Kebalikan dari byteToPoint
    count = 0
    temp = count * c.g
    while point != temp:
      count = count + 1
      temp = count * c.g
    return count
    

def encodekey(key: Tuple[dict[str, int], dict[str, int]]) -> Tuple[dict[str, str], dict[str, str]]:
  pubkey, privkey = key
  pubkey['x'] = hex(pubkey['x'])
  pubkey['y'] = hex(pubkey['y'])
  pubkey['curvename'] = pubkey['curvename']
  privkey['curvename'] = privkey['curvename']
  privkey['priv'] = hex(privkey['priv'])
  return (pubkey, privkey)


def decodekey(key: dict[str, str]) -> dict[str,int]:
  decoded = {}
  for k in key.keys():
    if k == 'curvename':
      decoded[k] = key[k]
    else:
      decoded[k] = int(key[k], 16)
  return decoded 

def encrypt(message: bytes, key: dict[str, int]) -> bytes:
  # Algoritma Elliptic Curve Elgamal
  x = key['x']
  y = key['y']
  cname = key['curvename']
  c = reg.get_curve(cname)
  pubkey = ec.Point(c,x,y)
  kvalue = random.randint(1,c.field.p)
  ciphertext = bytearray()
  bsize = sys.getsizeof(c.field.p)

  # Iterate Message
  for i in range(len(message)):
    msg = byteToPoint(message[i], c)
    first = kvalue * c.g #1st point
    second = msg + (kvalue * pubkey) #2nd point
    fx = first.x
    fy = first.y
    sx = second.x
    sy = second.y
    ciphertext.extend(fx.to_bytes(bsize, byteorder=sys.byteorder, signed=False))
    ciphertext.extend(fy.to_bytes(bsize, byteorder=sys.byteorder, signed=False))
    ciphertext.extend(sx.to_bytes(bsize, byteorder=sys.byteorder, signed=False))
    ciphertext.extend(sy.to_bytes(bsize, byteorder=sys.byteorder, signed=False))
  
  return ciphertext


def decrypt(message: bytes, key: dict[str,int]) -> bytes:
  # Algoritma Elliptic Curve Elgamal
  privkey = key['priv']
  cname = key['curvename']
  c = reg.get_curve(cname)
  bsize = sys.getsizeof(c.field.p)
  
  # For every cipherpoint:
  # first = cipherpoint[0] * privkey
  # second = cipherpoint[1] - first
  plain = []
  for i in range(0, len(message), 4*bsize):
    fx = int.from_bytes(message[i:i+bsize], byteorder=sys.byteorder, signed=False)
    fy = int.from_bytes(message[i+bsize:i+bsize*2], byteorder=sys.byteorder, signed=False)
    sx = int.from_bytes(message[i+bsize*2:i+bsize*3], byteorder=sys.byteorder, signed=False)
    sy = int.from_bytes(message[i+bsize*3:i+bsize*4], byteorder=sys.byteorder, signed=False)
    first = ec.Point(c,fx,fy)
    second = ec.Point(c,sx,sy)
    first = privkey * first
    second = second - first
    plain.append(pointToByte(second, c))

  # Decode back to message
  return bytearray(plain)


