from typing import Tuple
import random
import tinyec.ec as ec
import tinyec.registry as reg

def genkey() -> Tuple[dict[str, int], dict[str, int]]:
  """Fungsi pembangkit kunci ECC
     y^2 = x^3 + ax + b mod p"""
  c = reg.get_curve("secp192r1") # using a standard curve
  privkey = random.randint(1,c.field.p)
  pubkey = privkey * c.g
  return ({'priv' : privkey, 'curvename':c.name}, {'x': pubkey.x, 'y':pubkey.y, 'curvename':c.name})

def gety(a, b, p, x):
  # Hitung y jika diketahui a, b, p, x
  # Nilai bisa lebih dari 1
  # Jika array kosong, tidak ada y yang memenuhi
  y2 = (x**3 + a*x + b*x)%p
  y = []
  for i in range(0, p):
    temp = (i*i)%p
    if temp == y2:
      y.append(i)
  return y

def pickBase(a, b, p):
  # Memilih titik random pada kurva
  x = random.randint(0, p)
  y = gety(a, b, p, x)
  while len(y) == 0:
    x = x + 1
    if(x > p-1):
      x = 0
    y = gety(a, b, p, x)
  return (x, y[0])

def byteToPoint(m, k, a, b, p):
  # Mengkonversi m = 0-255 menjadi titik pada kurva sesuai k yang disetujui
  # (Metode Kolbitz)
  x = m*k + 1
  y = gety(a, b, p, x)
  while len(y) == 0:
    x = x + 1
    y = gety(a, b, p, x)

  return (x, y[0]) # not ec.Point yet

def pointToByte(point, k):
    # Kebalikan dari byteToPoint
    # point = (x, y)
    x = point.x
    return (x-1)//k

def encodekey(key: Tuple[dict[str, int], dict[str, int]]) -> Tuple[dict[str, str], dict[str, str]]:
  pass

def decodekey(key: dict[str, str]) -> dict[str,int]:
  pass 

def encrypt(message: bytes, key: dict[str, int]) -> bytes:
  # Algoritma Elliptic Curve Elgamal
  x = key['x']
  y = key['y']
  cname = key['curvename']
  c = reg.get_curve(cname)
  pubkey = ec.Point(c,x,y)
  kvalue = random.randint(1,c.field.p)

  ciphertext = bytearray()

  # Iterate Message
  for x in message:
    msg = byteToPoint(message, 1, c.a, c.b, c.field.p)
    first = kvalue * c.g #1st point
    second = msg + (kvalue * pubkey) #2nd point
    cipherpoint = (first, second)
    # ubah ke bytes?


def decrypt(message: bytes, key: dict[str,int]) -> bytes:
  # Algoritma Elliptic Curve Elgamal
  privkey = key['priv']
  cname = key['curvename']
  c = reg.get_curve(cname)
  
  # For every cipherpoint:
  # first = cipherpoint[0] * privkey
  # second = cipherpoint[1] - first

  # Decode back to message
  # ...


