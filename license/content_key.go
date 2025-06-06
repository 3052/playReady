package license

import (
   "41.neocities.org/playReady/crypto"
   "encoding/binary"
   "errors"
)

func (c *ContentKey) Decrypt(key crypto.EcKey, auxKeys *AuxKeys) error {
   switch c.CipherType {
   case 3:
      decrypted := c.ECC256(key)
      c.Integrity.Decode(decrypted)
      decrypted = decrypted[16:]
      c.Key.Decode(decrypted)
      return nil
   case 6:
      return errors.New("scalable")
   }
   return errors.New("cant decrypt key")
}

func (c *ContentKey) ECC256(key crypto.EcKey) []byte {
   var elgamal crypto.ElGamal
   decrypted := elgamal.Decrypt(c.Value, key.Key.D)

   return decrypted
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

func XorKey(root, second []byte) []byte {
   data := make([]byte, len(second))
   copy(data, root)
   for i := range 16 {
      data[i] ^= second[i]
   }
   return data
}

