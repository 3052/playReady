package playReady

import (
   "crypto/ecdsa"
   "encoding/binary"
   "encoding/hex"
   "errors"
)

func (c *ContentKey) decrypt(key *ecdsa.PrivateKey, auxKeys *auxKeys) error {
   switch c.CipherType {
   case 3:
      decrypted := elGamalDecrypt(c.Value, key)
      c.Integrity.Decode(decrypted)
      decrypted = decrypted[16:]
      copy(c.Key[:], decrypted)
      return nil
   case 6:
      return c.scalable(key, auxKeys)
   }
   return errors.New("cannot decrypt key")
}

func (c *ContentKey) scalable(key *ecdsa.PrivateKey, auxKeys *auxKeys) error {
   rootKeyInfo := c.Value[:144]
   rootKey := rootKeyInfo[128:]
   leafKeys := c.Value[144:]
   decrypted := elGamalDecrypt(rootKeyInfo[:128], key)
   var (
      ci [16]byte
      ck [16]byte
   )
   for i := range 16 {
      ci[i] = decrypted[i*2]
      ck[i] = decrypted[i*2+1]
   }
   magicConstantZero, err := c.magicConstantZero()
   if err != nil {
      return err
   }
   rgbUplinkXkey := xorKey(ck[:], magicConstantZero)
   contentKeyPrime, err := aesECBHandler(rgbUplinkXkey, ck[:], true)
   if err != nil {
      return err
   }
   auxKeyCalc, err := aesECBHandler(auxKeys.Keys[0].Key[:], contentKeyPrime, true)
   if err != nil {
      return err
   }
   var zero [16]byte
   upLinkXkey := xorKey(auxKeyCalc, zero[:])
   oSecondaryKey, err := aesECBHandler(rootKey, ck[:], true)
   if err != nil {
      return err
   }
   rgbKey, err := aesECBHandler(leafKeys, upLinkXkey, true)
   if err != nil {
      return err
   }
   rgbKey, err = aesECBHandler(rgbKey, oSecondaryKey, true)
   if err != nil {
      return err
   }
   c.Integrity.Decode(rgbKey[:])
   rgbKey = rgbKey[16:]
   copy(c.Key[:], rgbKey)
   return nil
}

// magicConstantZero returns a specific hex-decoded byte slice.
func (*ContentKey) magicConstantZero() ([]byte, error) {
   return hex.DecodeString("7ee9ed4af773224f00b8ea7efb027cbb")
}

// decode decodes a byte slice into a ContentKey structure.
func (c *ContentKey) decode(data []byte) {
   c.KeyID.Decode(data[:])
   data = data[16:]
   c.KeyType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.CipherType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.Value = data[:c.Length]
}

type ContentKey struct {
   KeyID      GUID
   KeyType    uint16
   CipherType uint16
   Length     uint16
   Value      []byte
   Integrity  GUID
   Key        [16]byte
}
