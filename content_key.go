package playReady

import (
   "encoding/binary"
   "encoding/hex"
   "errors"
)

func (c *ContentKey) Scalable(key EcKey, aux_keys *AuxKeys) error {
   rootKeyInfo := c.Value[:144]
   rootKey := rootKeyInfo[128:]
   leafKeys := c.Value[144:]
   var el_gamal ElGamal
   decrypted := el_gamal.Decrypt(rootKeyInfo[:128], key.Key.D)
   var CI [16]byte
   var CK [16]byte
   for i := range 16 {
      CI[i] = decrypted[i*2]
      CK[i] = decrypted[i*2+1]
   }
   magicConstantZero, err := hex.DecodeString("7ee9ed4af773224f00b8ea7efb027cbb")
   if err != nil {
      return err
   }
   rgbUplinkXKey := XorKey(CK[:], magicConstantZero)
   var aes Aes
   contentKeyPrime := aes.EncryptECB(CK[:], rgbUplinkXKey)
   auxKeyCalc := aes.EncryptECB(contentKeyPrime, aux_keys.Keys[0].Key[:])
   UpLinkXKey := XorKey(auxKeyCalc, new([16]byte)[:])
   oSecondaryKey := aes.EncryptECB(CK[:], rootKey)
   rgbKey := aes.EncryptECB(UpLinkXKey, leafKeys)
   rgbKey = aes.EncryptECB(oSecondaryKey, rgbKey)
   c.Integrity.Decode(rgbKey[:])
   rgbKey = rgbKey[16:]
   c.Key.Decode(rgbKey[:])
   return nil
}

func (c *ContentKey) Decrypt(key EcKey, aux_keys *AuxKeys) error {
   switch c.CipherType {
   case 3:
      decrypted := c.ECC256(key)
      c.Integrity.Decode(decrypted)
      decrypted = decrypted[16:]
      c.Key.Decode(decrypted)
      return nil
   case 6:
      return c.Scalable(key, aux_keys)
   }
   return errors.New("cant decrypt key")
}

func (c *ContentKey) ECC256(key EcKey) []byte {
   var el_gamal ElGamal
   return el_gamal.Decrypt(c.Value, key.Key.D)
}

type ContentKey struct {
   KeyId      Guid
   KeyType    uint16
   CipherType uint16
   Length     uint16
   Value      []byte
   Integrity  Guid
   Key        Guid
}

func (c *ContentKey) Decode(data []byte) error {
   c.KeyId.Decode(data[:])
   data = data[16:]
   c.KeyType = binary.BigEndian.Uint16(data)
   data = data[2:]

   c.CipherType = binary.BigEndian.Uint16(data)
   data = data[2:]

   c.Length = binary.BigEndian.Uint16(data)
   data = data[2:]

   c.Value = make([]byte, c.Length)

   copy(c.Value[:], data)

   return nil
}
