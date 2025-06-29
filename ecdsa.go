package playReady

import (
   "41.neocities.org/playReady/xml"
   "crypto/sha256"
   "encoding/hex"
   "errors"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/curve"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/ecdsa"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/math"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/point"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/privatekey"
   "math/big"
   "slices"
)

func elGamalDecrypt(data []byte, key *big.Int) (*big.Int, *big.Int) {
   // Unmarshal C1 component
   c1X := new(big.Int).SetBytes(data[:32])
   c1Y := new(big.Int).SetBytes(data[32:64])
   C1 := point.Point{X: c1X, Y: c1Y}
   // Unmarshal C2 component
   c2X := new(big.Int).SetBytes(data[64:96])
   c2Y := new(big.Int).SetBytes(data[96:])
   C2 := point.Point{X: c2X, Y: c2Y}
   g1 := curve.Prime256v1
   // Calculate shared secret s = C1^x
   S := math.Multiply(C1, key, g1.N, g1.A, g1.P)
   // Invert the point for subtraction
   S.Y.Neg(S.Y)
   S.Y.Mod(S.Y, g1.P)
   // Recover message point: M = C2 - s
   M := math.Add(C2, S, g1.A, g1.P)
   return M.X, M.Y
}

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

func elGamalEncrypt(data, key *xmlKey) []byte {
   g := curve.Prime256v1
   m := point.Point{X: data.X, Y: data.Y}
   s := point.Point{X: key.X, Y: key.Y}
   C2 := math.Add(m, s, g.A, g.P)
   return slices.Concat(
      g.G.X.Bytes(),
      g.G.Y.Bytes(),
      C2.X.Bytes(),
      C2.Y.Bytes(),
   )
}

func (x *xmlKey) New() {
   point := curve.Prime256v1.G
   x.X, x.Y = point.X, point.Y
   x.X.FillBytes(x.RawX[:])
}

type xmlKey struct {
   X *big.Int
   Y *big.Int
   RawX [32]byte
}

func Sign2(key *privatekey.PrivateKey, hash []byte) ([]byte, error) {
   // SIGN DOES SHA-256 ITSELF
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
