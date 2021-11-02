from typing import Tuple
import random

def genkey() -> Tuple[dict[str, int], dict[str, int]]:
  """Fungsi pembangkit kunci ECC
     y^2 = x^3 + ax + b mod p"""
  a = -1
  b = 188
  p = 751
  privatekey = random.randint(1,p)
  randompoint = pickBase(a,b,p)

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

  return (x, y[0])

def pointToByte(point, k):
    # Kebalikan dari byteToPoint
    # point = (x, y)
    x = point[0]
    return (x-1)//k

def encodekey(key: Tuple[dict[str, int], dict[str, int]]) -> Tuple[dict[str, str], dict[str, str]]:
  pass

def decodekey(key: dict[str, str]) -> dict[str,int]:
  pass 

def encrypt(message: bytes, key: dict[str, int]) -> bytes:
  pass

def decrypt(message: bytes, key: dict[str,int]) -> bytes:
  pass
