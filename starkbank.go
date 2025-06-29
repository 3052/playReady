package playReady

import (
   "41.neocities.org/playReady/xml"
   "bytes"
   "crypto/sha256"
   "errors"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/curve"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/ecdsa"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/math"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/point"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/privatekey"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/publickey"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/signature"
   "math/big"
   "slices"
)

func elGamalEncrypt(data, key *xmlKey) []byte {
   g := curve.Prime256v1
   m := point.Point{X: data.X, Y: data.Y}
   s := point.Point{X: key.X, Y: key.Y}
   C2 := math.Add(m, s, g.A, g.P)
   return slices.Concat(
      g.G.X.Bytes(), g.G.Y.Bytes(), C2.X.Bytes(), C2.Y.Bytes(),
   )
}

func (c *Certificate) verify(pubKey []byte) bool {
   if !bytes.Equal(c.Signature.IssuerKey, pubKey) {
      return false
   }
   publicKey := publickey.PublicKey{
      Point: point.Point{
         X:     new(big.Int).SetBytes(pubKey[:32]),
         Y:     new(big.Int).SetBytes(pubKey[32:]),
      },
      Curve: curve.Prime256v1,
   }
   message := c.Append(nil)
   message = message[:c.LengthToSignature]
   sign := c.Signature.Signature
   r := new(big.Int).SetBytes(sign[:32])
   s := new(big.Int).SetBytes(sign[32:])
   return ecdsa.Verify(
      string(message),
      signature.Signature{R: *r, S: *s},
      &publicKey,
   )
}

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

func (x *xmlKey) New() {
   point := curve.Prime256v1.G
   x.X, x.Y = point.X, point.Y
   x.X.FillBytes(x.RawX[:])
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

func (c *Chain) Leaf(
   modelKey2 *privatekey.PrivateKey,
   signEncryptKey *point.Point,
) error {
   if !bytes.Equal(
      c.Certificates[0].KeyInfo.Keys[0].PublicKey[:],
      func() []byte {
         p := modelKey2.PublicKey().Point
         return append(p.X.Bytes(), p.Y.Bytes()...)
      }(),
   ) {
      return errors.New("zgpriv not for cert")
   }
   if !c.verify() {
      return errors.New("cert is not valid")
   }
   var cert Certificate
   copy(cert.Magic[:], "CERT")
   cert.Version = 1 // required
   {
      // SCALABLE with SL2000, SUPPORTS_PR3_FEATURES
      var features CertFeatures
      features.New(0xD)
      cert.Features = features.ftlv(0, 5)
   }
   {
      sum := sha256.Sum256(
         append(signEncryptKey.X.Bytes(), signEncryptKey.Y.Bytes()...),
      )
      cert.Info = &CertificateInfo{}
      cert.Info.New(c.Certificates[0].Info.SecurityLevel, sum[:])
   }
   cert.KeyInfo = &KeyInfo{}
   cert.KeyInfo.New(
      append(signEncryptKey.X.Bytes(), signEncryptKey.Y.Bytes()...),
   )
   {
      cert.LengthToSignature, cert.Length = cert.size()
      signature, err := Sign2(modelKey2, cert.Append(nil))
      if err != nil {
         return err
      }
      cert.Signature = &CertSignature{}
      err = cert.Signature.New(
         signature,
         func() []byte {
            p := modelKey2.PublicKey().Point
            return append(p.X.Bytes(), p.Y.Bytes()...)
         }(),
      )
      if err != nil {
         return err
      }
   }
   c.CertCount += 1
   c.Certificates = slices.Insert(c.Certificates, 0, cert)
   c.Length += cert.Length
   return nil
}

func (l *License) Decrypt(
   signEncrypt *privatekey.PrivateKey, data []byte,
) error {
   var envelope xml.EnvelopeResponse
   err := envelope.Unmarshal(data)
   if err != nil {
      return err
   }
   data = envelope.
      Body.
      AcquireLicenseResponse.
      AcquireLicenseResult.
      Response.
      LicenseResponse.
      Licenses.
      License
   err = l.decode(data)
   if err != nil {
      return err
   }
   if !bytes.Equal(
      l.EccKey.Value,
      func() []byte {
         p := signEncrypt.PublicKey().Point
         return append(p.X.Bytes(), p.Y.Bytes()...)
      }(),
   ) {
      return errors.New("license response is not for this device")
   }
   err = l.ContentKey.decrypt(signEncrypt.Secret, l.AuxKeys)
   if err != nil {
      return err
   }
   return l.verify(data)
}
