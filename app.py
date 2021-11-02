import json
import sys
from flask import Flask,render_template,request
from algos import rsa, eg, paillier

app = Flask(__name__)

@app.get('/')
def index():
  return render_template('index.html')

@app.get('/generatekey')
def genkey_frontend():
  return render_template('genkey.html')

@app.post('/generatekey')
def genkey():
  alg = request.form['alg']
  bit = request.form['bits']
  if alg == 'RSA':
    pubkey, privkey = rsa.encodekey(rsa.genkey(int(bit)))
  elif alg == 'EG':
    pubkey, privkey = eg.encodekey(eg.genkey())
  elif alg == 'Paillier':
    pubkey, privkey = paillier.encodekey(paillier.genkey())
  return {'pubkey': pubkey, 'privkey': privkey}

@app.get('/encryptdecrypt')
def ed_frontend():
  return render_template('encdec.html')

@app.post('/encryptdecrypt')
def ed():
  alg = request.form['alg']
  op = request.form['op']
  try:
    msg = bytearray(request.form['message'], 'utf8')
  except KeyError:
    msg = request.files['message'].read()
  try:
    key = request.form['key']
  except KeyError:
    key = request.files['key'].read()
  if alg == 'RSA':
    key = rsa.decodekey(json.loads(key))
    if op == 'enc':
      return rsa.encrypt(msg, key)
    elif op == 'dec':
      return rsa.decrypt(msg, key)
  elif alg == 'EG':
    key = eg.decodekey(json.loads(key))
    if op == 'enc':
      return eg.encrypt(msg, key)
    elif op == 'dec':
      return eg.decrypt(msg, key)
  elif alg == 'Paillier':
    key = paillier.decodekey(json.loads(key))
    if op == 'enc':
      return paillier.encrypt(msg, key)
    elif op == 'dec':
      return paillier.decrypt(msg, key)
  return alg

if __name__ == "__main__":
  app.run()
