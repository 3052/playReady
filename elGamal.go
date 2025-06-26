package playReady

import (
   "crypto/ecdsa"
   "crypto/elliptic"
   "errors"
   "math/big"
   "slices"
)

type ContentKey struct {
   KeyId      [16]byte
   KeyType    uint16
   CipherType uint16
   Length     uint16
   Value      []byte

   Integrity [16]byte
   Key       [16]byte
}

func elGamalEncrypt(data, key *ecdsa.PublicKey) []byte {
   g := elliptic.P256()
   y := big.NewInt(1) // In a real scenario, y should be truly random
   c1x, c1y := g.ScalarBaseMult(y.Bytes())
   sX, sY := g.ScalarMult(key.X, key.Y, y.Bytes())
   c2X, c2Y := g.Add(data.X, data.Y, sX, sY)
   return slices.Concat(c1x.Bytes(), c1y.Bytes(), c2X.Bytes(), c2Y.Bytes())
}

func elGamalDecrypt(data []byte, key *ecdsa.PrivateKey) (*big.Int, *big.Int) {
   curve := elliptic.P256()
   // Unmarshal C1 component
   c1X := new(big.Int).SetBytes(data[:32])
   c1Y := new(big.Int).SetBytes(data[32:64])
   // Unmarshal C2 component
   c2X := new(big.Int).SetBytes(data[64:96])
   c2Y := new(big.Int).SetBytes(data[96:])
   // Calculate shared secret s = C1^x
   sX, sY := curve.ScalarMult(c1X, c1Y, key.D.Bytes())
   // Invert the point for subtraction
   sY.Neg(sY)
   sY.Mod(sY, curve.Params().P)
   // Recover message point: M = C2 - s
   return curve.Add(c2X, c2Y, sX, sY)
}

func (c *ContentKey) decrypt(key *ecdsa.PrivateKey, aux *AuxKeys) error {
   switch c.CipherType {
   case 3:
      messageX, _ := elGamalDecrypt(c.Value, key)
      decrypted := messageX.Bytes()
      n := copy(c.Integrity[:], decrypted)
      decrypted = decrypted[n:]
      copy(c.Key[:], decrypted)
      return nil
   case 6:
      return c.scalable(key, aux)
   }
   return errors.New("cannot decrypt key")
}

func (c *ContentKey) scalable(key *ecdsa.PrivateKey, aux *AuxKeys) error {
   rootKeyInfo, leafKeys := c.Value[:144], c.Value[144:]
   rootKey := rootKeyInfo[128:]
   messageX, _ := elGamalDecrypt(rootKeyInfo[:128], key)
   decrypted := messageX.Bytes()
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
   contentKeyPrime, err := aesEcbEncrypt(rgbUplinkXkey, ck[:])
   if err != nil {
      return err
   }
   auxKeyCalc, err := aesEcbEncrypt(aux.Keys[0].Key[:], contentKeyPrime)
   if err != nil {
      return err
   }
   oSecondaryKey, err := aesEcbEncrypt(rootKey, ck[:])
   if err != nil {
      return err
   }
   rgbKey, err := aesEcbEncrypt(leafKeys, auxKeyCalc)
   if err != nil {
      return err
   }
   rgbKey, err = aesEcbEncrypt(rgbKey, oSecondaryKey)
   if err != nil {
      return err
   }
   n := copy(c.Integrity[:], rgbKey)
   rgbKey = rgbKey[n:]
   copy(c.Key[:], rgbKey)
   return nil
}
