package playReady

import (
   "41.neocities.org/playReady/xml"
   "crypto/ecdsa"
   "crypto/elliptic"
   "encoding/hex"
   "errors"
   "math/big"
   "slices"
)

func newLa(m *ecdsa.PublicKey, cipherData []byte, kid string) xml.La {
   return xml.La{
      XmlNs:   "http://schemas.microsoft.com/DRM/2007/03/protocols",
      Id:      "SignedData",
      Version: "1",
      ContentHeader: xml.ContentHeader{
         WrmHeader: xml.WrmHeader{
            XmlNs:   "http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader",
            Version: "4.0.0.0",
            Data: xml.WrmHeaderData{
               ProtectInfo: xml.ProtectInfo{
                  KeyLen: "16",
                  AlgId:  "AESCTR",
               },
               Kid: kid,
            },
         },
      },
      EncryptedData: xml.EncryptedData{
         XmlNs: "http://www.w3.org/2001/04/xmlenc#",
         Type:  "http://www.w3.org/2001/04/xmlenc#Element",
         EncryptionMethod: xml.Algorithm{
            Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
         },
         KeyInfo: xml.KeyInfo{
            XmlNs: "http://www.w3.org/2000/09/xmldsig#",
            EncryptedKey: xml.EncryptedKey{
               XmlNs: "http://www.w3.org/2001/04/xmlenc#",
               EncryptionMethod: xml.Algorithm{
                  Algorithm: "http://schemas.microsoft.com/DRM/2007/03/protocols#ecc256",
               },
               KeyInfo: xml.EncryptedKeyInfo{
                  XmlNs:   "http://www.w3.org/2000/09/xmldsig#",
                  KeyName: "WMRMServer",
               },
               CipherData: xml.CipherData{
                  CipherValue: elGamalEncrypt(m, elGamalKeyGeneration()),
               },
            },
         },
         CipherData: xml.CipherData{
            CipherValue: cipherData,
         },
      },
   }
}

func elGamalEncrypt(m, h *ecdsa.PublicKey) []byte {
   // generator
   g := elliptic.P256()
   // choose an integer y randomly
   y := big.NewInt(1) // In a real scenario, y should be truly random
   // compute c1 := g^y
   c1X, c1Y := g.ScalarBaseMult(y.Bytes())
   // Calculate shared secret s = (h^y)
   sX, sY := g.ScalarMult(h.X, h.Y, y.Bytes())
   // Second component C2 = M + s (point addition for elliptic curves)
   c2X, c2Y := g.Add(m.X, m.Y, sX, sY)
   return slices.Concat(c1X.Bytes(), c1Y.Bytes(), c2X.Bytes(), c2Y.Bytes())
}

func elGamalKeyGeneration() *ecdsa.PublicKey {
   data, _ := hex.DecodeString(wmrmPublicKey)
   var key ecdsa.PublicKey
   key.X = new(big.Int).SetBytes(data[:32])
   key.Y = new(big.Int).SetBytes(data[32:])
   return &key
}

const wmrmPublicKey = "C8B6AF16EE941AADAA5389B4AF2C10E356BE42AF175EF3FACE93254E7B0B3D9B982B27B5CB2341326E56AA857DBFD5C634CE2CF9EA74FCA8F2AF5957EFEEA562"

func elGamalDecrypt(ciphertext []byte, x *ecdsa.PrivateKey) []byte {
   // generator
   g := elliptic.P256()
   // Unmarshal C1 component
   c1X := new(big.Int).SetBytes(ciphertext[:32])
   c1Y := new(big.Int).SetBytes(ciphertext[32:64])
   // Unmarshal C2 component
   c2X := new(big.Int).SetBytes(ciphertext[64:96])
   c2Y := new(big.Int).SetBytes(ciphertext[96:])
   // Calculate shared secret s = C1^x
   sX, sY := g.ScalarMult(c1X, c1Y, x.D.Bytes())
   // Invert the point for subtraction
   sY.Neg(sY)
   sY.Mod(sY, g.Params().P)
   // Recover message point: M = C2 - s
   mX, mY := g.Add(c2X, c2Y, sX, sY)
   return append(mX.Bytes(), mY.Bytes()...)
}

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
