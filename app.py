from flask import Flask,render_template,request
from algos import rsa

app = Flask(__name__)

@app.get('/')
def index():
  return render_template('index.html')

@app.get('/generatekey')
def genkey_frontend():
  return render_template('genkey.html')

@app.post('/generatekey')
def genkey():
  return 'OK'

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
    key = bytearray(request.form['key'], 'utf8')
  except KeyError:
    key = request.files['key'].read()
  return alg

if __name__ == "__main__":
  app.run()
