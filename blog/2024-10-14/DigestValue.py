def get_cipherdata(self, dev, xmlkey):
   dchain = dev.get_cert_chain()
   chain_data = dchain.body()
   b64_certchain = Crypto.base64_encode(chain_data)
   s = ""
   s += self.CERT_CHAIN_START()
   s += " "
   s += b64_certchain
   s += " "
   s += self.CERT_CHAIN_END()
   cert_data = self.pad16(s)
   enc_cert_data = Crypto.aes_cbc_encrypt(cert_data, xmlkey.aes_iv(), xmlkey.aes_key())
   iv_len = len(xmlkey.aes_iv())
   enc_data_len = len(enc_cert_data)
   ciphertext = [0] * (iv_len + enc_data_len)
   ciphertext[:iv_len] = xmlkey.aes_iv()
   ciphertext[iv_len:] = enc_cert_data
   return Crypto.base64_encode(ciphertext)

# github.com/Dreamer269/Unofficial-DRM/blob/main/modules/playready/device.py
class Device:
   def get_cert_chain(self):
      if self.cert_chain is None or Device.changed() or (self.cert is not None and self.cert.get_seclevel() != Device.cur_SL()):
         if MSPR.fixed_identity():
            r = ECC.make_bi(Utils.reverse_hex_string("062dd035241da79eedbc2abc9d99ab5b159788bb78d56aedcc3b603018ec02f7"))
            ECC.set_random(r)
         gcert = Device.get_group_cert()
         self.cert_chain = gcert.insert(self.get_cert())
         self.cert_chain.save("genchain")
      return self.cert_chain

class XmlKey:
   def aes_iv(self):
      if self.aes_iv is None:
          self.setup_aes_key()
      return self.aes_iv

   def bytes(self):
      data = [0] * (2 * AES_KEY_SIZE)
      data[:AES_KEY_SIZE] = self.aes_iv()
      data[AES_KEY_SIZE:2 * AES_KEY_SIZE] = self.aes_key()
      return data

   def setup_aes_key(self):
      shared_data = ECC.bi_bytes(self.shared_key)
      self.aes_iv = [0] * AES_KEY_SIZE
      self.aes_key = [0] * AES_KEY_SIZE
      self.aes_iv[:AES_KEY_SIZE] = shared_data[:AES_KEY_SIZE]
      self.aes_key[:AES_KEY_SIZE] = shared_data[0x10:AES_KEY_SIZE]

#################################################################################

def get_nonce(self):
   data = ECC.bi_bytes(ECC.random())
   nonce = [0] * NONCE_SIZE
   nonce[:NONCE_SIZE] = data[:NONCE_SIZE]
   return Crypto.base64_encode(nonce)

class MSPR:
   AES_KEY_SIZE = 0x10
   NONCE_SIZE = 0x10
   WMRMECC256PubKey = "C8B6AF16EE941AADAA5389B4AF2C10E356BE42AF175EF3FACE93254E7B0B3D9B982B27B5CB2341326E56AA857DBFD5C634CE2CF9EA74FCA8F2AF5957EFEEA562"

def get_keydata(self, xmlkey):
   keydata = xmlkey.bytes()
   encrypted = Crypto.ecc_encrypt(keydata, getWMRMpubkey())
   return Crypto.base64_encode(encrypted)

xkey = self.XmlKey()
keydata = self.get_keydata(xkey)
cipherdata = self.get_cipherdata(dev, xkey)
digest_content = self.build_digest_content(wrmheader, nonce, keydata, cipherdata)
digest_bytes = Crypto.SHA256(digest_content.getBytes())
