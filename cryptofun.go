package playReady

import (
   "41.neocities.org/playReady/xml"
   "bytes"
   //"crypto/elliptic"
   "crypto/sha256"
   "errors"
   "github.com/arnaucube/cryptofun/ecc"
   "github.com/arnaucube/cryptofun/ecdsa"
   "github.com/arnaucube/cryptofun/elgamal"
   "math/big"
   "slices"
)

// nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
func p256() (ec ecc.EC, g ecc.Point, n *big.Int) {
   ec.A = big.NewInt(-3)
   ec.B, _ = new(big.Int).SetString("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
   ec.Q, _ = new(big.Int).SetString("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10)
   g.X, _ = new(big.Int).SetString("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
   g.Y, _ = new(big.Int).SetString("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)
   n, _ = new(big.Int).SetString("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10)
   return
}

func (c *Certificate) verify(pubK []byte) (bool, error) {
   if !bytes.Equal(c.Signature.IssuerKey, pubK) {
      return false, nil
   }
   var dsa ecdsa.DSA
   dsa.EC, dsa.G, dsa.N = p256()
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
   dsa.EC, dsa.G, dsa.N = p256()
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

func sign(privK *big.Int, hashVal []byte) ([]byte, error) {
   var dsa ecdsa.DSA
   dsa.EC, dsa.G, dsa.N = p256()
   rs, err := dsa.Sign(
      new(big.Int).SetBytes(hashVal), privK, big.NewInt(1),
   )
   if err != nil {
      return nil, err
   }
   return append(rs[0].Bytes(), rs[1].Bytes()...), nil
}

func elGamalEncrypt(m, pubK *ecc.Point) ([]byte, error) {
   var eg elgamal.EG
   eg.EC, eg.G, eg.N = p256()
   c, err := eg.Encrypt(*m, *pubK, big.NewInt(1))
   if err != nil {
      return nil, err
   }
   return slices.Concat(
      c[0].X.Bytes(), c[0].Y.Bytes(), c[1].X.Bytes(), c[1].Y.Bytes(),
   ), nil
}

func elGamalDecrypt(data []byte, privK *big.Int) (ecc.Point, error) {
   var eg elgamal.EG
   eg.EC, eg.G, eg.N = p256()
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
   dsa.EC, dsa.G, dsa.N = p256()
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

func (c *Chain) RequestBody(signEncrypt *big.Int, kid []byte) ([]byte, error) {
   _, g, _ := p256()
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
