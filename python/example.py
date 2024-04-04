import json
import secrets

from base64 import b64encode
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

def asdf():
  header = b"header"
  plaintext = b'Hello world'
  key = secrets.token_bytes(32)
  cipher = ChaCha20_Poly1305.new(key=key)
  cipher.update(header)
  ciphertext, tag = cipher.encrypt_and_digest(plaintext)

  jk = [ 'nonce', 'header', 'ciphertext', 'tag' ]
  jv = [ b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag) ]
  result = json.dumps(dict(zip(jk, jv)))

  print(result)

if __name__ == '__main__':
    asdf()
