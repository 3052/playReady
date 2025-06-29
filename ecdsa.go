package playReady

import (
   "41.neocities.org/playReady/xml"
   "crypto/elliptic"
   "crypto/sha256"
   "encoding/hex"
   "errors"
   "math/big"
   "slices"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/privatekey"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/ecdsa"
)

//func (c *Certificate) verify(pubKey []byte) bool {
//   if !bytes.Equal(c.Signature.IssuerKey, pubKey) {
//      return false
//   }
//   publicKey := ecdsa.PublicKey{
//      Curve: elliptic.P256(), // Assuming P256 curve
//      X:     new(big.Int).SetBytes(pubKey[:32]),
//      Y:     new(big.Int).SetBytes(pubKey[32:]),
//   }
//   data := c.Append(nil)
//   data = data[:c.LengthToSignature]
//   signatureDigest := sha256.Sum256(data)
//   signature := c.Signature.Signature
//   r := new(big.Int).SetBytes(signature[:32])
//   s := new(big.Int).SetBytes(signature[32:])
//   return ecdsa.Verify(&publicKey, signatureDigest[:], r, s)
//}

func Sign2(key *privatekey.PrivateKey, hash []byte) ([]byte, error) {
   data := ecdsa.Sign(string(hash), key)
   return append(data.R.Bytes(), data.S.Bytes()...), nil
}

func (c *Chain) RequestBody(
   signEncrypt2 *privatekey.PrivateKey,
   kid []byte,
) ([]byte, error) {
   var key xmlKey
   key.New()
   cipherData, err := c.cipherData(&key)
   if err != nil {
      return nil, err
   }
   la := newLa(&key, cipherData, kid)
   laData, err := la.Marshal()
   if err != nil {
      return nil, err
   }
   laDigest := sha256.Sum256(laData)
   signedInfo := xml.SignedInfo{
      XmlNs: "http://www.w3.org/2000/09/xmldsig#",
      Reference: xml.Reference{
         Uri:         "#SignedData",
         DigestValue: laDigest[:],
      },
   }
   signedData, err := signedInfo.Marshal()
   if err != nil {
      return nil, err
   }
   signature, err := Sign2(signEncrypt2, signedData)
   if err != nil {
      return nil, err
   }
   envelope := xml.Envelope{
      Soap: "http://schemas.xmlsoap.org/soap/envelope/",
      Body: xml.Body{
         AcquireLicense: &xml.AcquireLicense{
            XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols",
            Challenge: xml.Challenge{
               Challenge: xml.InnerChallenge{
                  XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols/messages",
                  La:    la,
                  Signature: xml.Signature{
                     SignedInfo:     signedInfo,
                     SignatureValue: signature,
                  },
               },
            },
         },
      },
   }
   return envelope.Marshal()
}

func newLa(m *xmlKey, cipherData, kid []byte) *xml.La {
   return &xml.La{
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

func elGamalKeyGeneration() *xmlKey {
   data, _ := hex.DecodeString(wmrmPublicKey)
   var key xmlKey
   key.X = new(big.Int).SetBytes(data[:32])
   key.Y = new(big.Int).SetBytes(data[32:])
   return &key
}

type Filler byte

func (f Filler) Read(data []byte) (int, error) {
   for index := range data {
      data[index] = byte(f)
   }
   return len(data), nil
}

type xmlKey struct {
   X *big.Int
   Y *big.Int
   RawX [32]byte
}

func (x *xmlKey) aesIv() []byte {
   return x.RawX[:16]
}

func (x *xmlKey) aesKey() []byte {
   return x.RawX[16:]
}

func (c *ContentKey) decrypt(key *big.Int, aux *AuxKeys) error {
   switch c.CipherType {
   case 3:
      messageX, _ := elGamalDecrypt(c.Value, key)
      c.Value = messageX.Bytes()
      return nil
   case 6:
      return c.scalable(key, aux)
   }
   return errors.New("cannot decrypt key")
}

func (c *ContentKey) scalable(key *big.Int, aux *AuxKeys) error {
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
   constantZero, err := hex.DecodeString(magicConstantZero)
   if err != nil {
      return err
   }
   rgbUplinkXkey := xorKey(ck[:], constantZero)
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
   c.Value, err = aesEcbEncrypt(leafKeys, auxKeyCalc)
   if err != nil {
      return err
   }
   c.Value, err = aesEcbEncrypt(c.Value, oSecondaryKey)
   if err != nil {
      return err
   }
   return nil
}

func (x *xmlKey) New() {
   param := elliptic.P256().Params()
   x.X, x.Y = param.Gx, param.Gy
   x.X.FillBytes(x.RawX[:])
}

func elGamalDecrypt(data []byte, key *big.Int) (*big.Int, *big.Int) {
   curve := elliptic.P256()
   // Unmarshal C1 component
   c1X := new(big.Int).SetBytes(data[:32])
   c1Y := new(big.Int).SetBytes(data[32:64])
   // Unmarshal C2 component
   c2X := new(big.Int).SetBytes(data[64:96])
   c2Y := new(big.Int).SetBytes(data[96:])
   // Calculate shared secret s = C1^x
   sX, sY := curve.ScalarMult(c1X, c1Y, key.Bytes())
   // Invert the point for subtraction
   sY.Neg(sY)
   sY.Mod(sY, curve.Params().P)
   // Recover message point: M = C2 - s
   return curve.Add(c2X, c2Y, sX, sY)
}

func elGamalEncrypt(data, key *xmlKey) []byte {
   curve := elliptic.P256()
   param := curve.Params()
   c2X, c2Y := curve.Add(data.X, data.Y, key.X, key.Y)
   return slices.Concat(
      param.Gx.Bytes(), param.Gy.Bytes(), c2X.Bytes(), c2Y.Bytes(),
   )
}
