package playReady

import (
   "41.neocities.org/playReady/xml"
   "bytes"
   "crypto/elliptic"
   "crypto/sha256"
   "errors"
   "github.com/arnaucube/cryptofun/ecc"
   "github.com/arnaucube/cryptofun/ecdsa"
   "github.com/arnaucube/cryptofun/elgamal"
   "math/big"
   "slices"
)

// nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
func p256() (ec ecc.EC, g ecc.Point) {
   params := elliptic.P256().Params()
   ec.A = big.NewInt(-3) // pkg.go.dev/crypto/elliptic#Curve
   ec.B = params.B
   ec.Q = params.P
   g.X = params.Gx
   g.Y = params.Gy
   return
}

func p256n() *big.Int {
   return elliptic.P256().Params().N
}

func (c *Certificate) verify(pubK []byte) (bool, error) {
   if !bytes.Equal(c.Signature.IssuerKey, pubK) {
      return false, nil
   }
   var dsa ecdsa.DSA
   dsa.EC, dsa.G = p256()
   dsa.N = p256n()
   message := c.Append(nil)
   message = message[:c.LengthToSignature]
   sign := c.Signature.Signature
   hashVal := func() *big.Int {
      sum := sha256.Sum256(message)
      return new(big.Int).SetBytes(sum[:])
   }()
   sig := [2]*big.Int{
      new(big.Int).SetBytes(sign[:32]),
      new(big.Int).SetBytes(sign[32:]),
   }
   return dsa.Verify(
      hashVal,
      sig,
      ecc.Point{
         X: new(big.Int).SetBytes(pubK[:32]),
         Y: new(big.Int).SetBytes(pubK[32:]),
      },
   )
}

func (c *Chain) Leaf(
   modelKey *big.Int,
   signEncryptKey *big.Int,
) error {
   var dsa ecdsa.DSA
   dsa.EC, dsa.G = p256()
   dsa.N = p256n()
   modelPub, err := dsa.PubK(modelKey)
   if err != nil {
      return err
   }
   if !bytes.Equal(
      c.Certificates[0].KeyInfo.Keys[0].PublicKey[:],
      append(modelPub.X.Bytes(), modelPub.Y.Bytes()...),
   ) {
      return errors.New("zgpriv not for cert")
   }
   ok, err := c.verify()
   if err != nil {
      return err
   }
   if !ok {
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
   signEncryptPub, err := dsa.PubK(signEncryptKey)
   if err != nil {
      return err
   }
   {
      sum := sha256.Sum256(
         append(signEncryptPub.X.Bytes(), signEncryptPub.Y.Bytes()...),
      )
      cert.Info = &CertificateInfo{}
      cert.Info.New(c.Certificates[0].Info.SecurityLevel, sum[:])
   }
   cert.KeyInfo = &KeyInfo{}
   cert.KeyInfo.New(
      append(signEncryptPub.X.Bytes(), signEncryptPub.Y.Bytes()...),
   )
   {
      cert.LengthToSignature, cert.Length = cert.size()
      hashVal := sha256.Sum256(cert.Append(nil))
      signature, err := sign(modelKey, hashVal[:])
      if err != nil {
         return err
      }
      cert.Signature = &CertSignature{}
      err = cert.Signature.New(
         signature,
         append(modelPub.X.Bytes(), modelPub.Y.Bytes()...),
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

// 5
func sign(privK *big.Int, hashVal []byte) ([]byte, error) {
   var dsa ecdsa.DSA
   dsa.EC, dsa.G = p256()
   dsa.N = p256n()
   rs, err := dsa.Sign(
      new(big.Int).SetBytes(hashVal), privK, big.NewInt(1),
   )
   if err != nil {
      return nil, err
   }
   return append(rs[0].Bytes(), rs[1].Bytes()...), nil
}

// 9
func elGamalEncrypt(m, pubK *ecc.Point) ([]byte, error) {
   var eg elgamal.EG
   eg.EC, eg.G = p256()
   eg.N = p256n()
   c, err := eg.Encrypt(*m, *pubK, big.NewInt(1))
   if err != nil {
      return nil, err
   }
   return slices.Concat(
      c[0].X.Bytes(), c[0].Y.Bytes(), c[1].X.Bytes(), c[1].Y.Bytes(),
   ), nil
}

// 19
func elGamalDecrypt(data []byte, privK *big.Int) (ecc.Point, error) {
   var eg elgamal.EG
   eg.EC, eg.G = p256()
   eg.N = p256n()
   // Unmarshal C1 component
   c1 := ecc.Point{
      X: new(big.Int).SetBytes(data[:32]),
      Y: new(big.Int).SetBytes(data[32:64]),
   }
   // Unmarshal C2 component
   c2 := ecc.Point{
      X: new(big.Int).SetBytes(data[64:96]),
      Y: new(big.Int).SetBytes(data[96:]),
   }
   return eg.Decrypt([2]ecc.Point{c1, c2}, privK)
}

// 35
func (l *License) Decrypt(
   signEncrypt *big.Int,
   data []byte,
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
   var dsa ecdsa.DSA
   dsa.EC, dsa.G = p256()
   dsa.N = p256n()
   pubK, err := dsa.PubK(signEncrypt)
   if err != nil {
      return err
   }
   if !bytes.Equal(
      l.EccKey.Value,
      append(pubK.X.Bytes(), pubK.Y.Bytes()...),
   ) {
      return errors.New("license response is not for this device")
   }
   err = l.ContentKey.decrypt(signEncrypt, l.AuxKeys)
   if err != nil {
      return err
   }
   return l.verify(data)
}

func (c *Chain) RequestBody(
   signEncrypt *big.Int,
   kid []byte,
) ([]byte, error) {
   _, g := p256()
   cipherData, err := c.cipherData(g.X)
   if err != nil {
      return nil, err
   }
   la, err := newLa(&g, cipherData, kid)
   if err != nil {
      return nil, err
   }
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
   hashVal := sha256.Sum256(signedData)
   signature, err := sign(signEncrypt, hashVal[:])
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
