package playReady

import (
   "41.neocities.org/playReady/xml"
   "bytes"
   "crypto/aes"
   "crypto/cipher"
   "crypto/sha256"
   "encoding/binary"
   "encoding/hex"
   "errors"
   "github.com/arnaucube/cryptofun/ecc"
   "github.com/arnaucube/cryptofun/ecdsa"
   "github.com/arnaucube/cryptofun/elgamal"
   "github.com/emmansun/gmsm/cbcmac"
   "github.com/emmansun/gmsm/padding"
   "math/big"
   "slices"
)

func (l *License) Decrypt(signEncrypt *big.Int, data []byte) error {
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

func elGamalKeyGeneration() *ecc.Point {
   data, _ := hex.DecodeString(wmrmPublicKey)
   return &ecc.Point{
      X: new(big.Int).SetBytes(data[:32]),
      Y: new(big.Int).SetBytes(data[32:]),
   }
}

func newLa(m *ecc.Point, cipherData, kid []byte) (*xml.La, error) {
   data, err := elGamalEncrypt(m, elGamalKeyGeneration())
   if err != nil {
      return nil, err
   }
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
                  CipherValue: data,
               },
            },
         },
         CipherData: xml.CipherData{
            CipherValue: cipherData,
         },
      },
   }, nil
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

func (l *License) verify(data []byte) error {
   signature := new(Ftlv).size() + l.Signature.size()
   data = data[:len(data)-signature]
   block, err := aes.NewCipher(l.ContentKey.integrity())
   if err != nil {
      return err
   }
   data = cbcmac.NewCMAC(block, aes.BlockSize).MAC(data)
   if !bytes.Equal(data, l.Signature.Data) {
      return errors.New("failed to decrypt the keys")
   }
   return nil
}

func (c *Chain) cipherData(x *big.Int) ([]byte, error) {
   xmlData := xml.Data{
      CertificateChains: xml.CertificateChains{
         CertificateChain: c.Encode(),
      },
      Features: xml.Features{
         Feature: xml.Feature{"AESCBC"}, // SCALABLE
      },
   }
   data, err := xmlData.Marshal()
   if err != nil {
      return nil, err
   }
   data = padding.NewPKCS7Padding(aes.BlockSize).Pad(data)
   xBytes := x.Bytes()
   iv, key := xBytes[:16], xBytes[16:]
   block, err := aes.NewCipher(key)
   if err != nil {
      return nil, err
   }
   cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, data)
   return append(iv, data...), nil
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

func (c *Chain) Leaf(modelKey, signEncryptKey *big.Int) error {
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

func (c *Chain) verify() (bool, error) {
   modelBase := c.Certificates[c.CertCount-1].Signature.IssuerKey
   for i := len(c.Certificates) - 1; i >= 0; i-- {
      ok, err := c.Certificates[i].verify(modelBase[:])
      if err != nil {
         return false, err
      }
      if !ok {
         return false, nil
      }
      modelBase = c.Certificates[i].KeyInfo.Keys[0].PublicKey[:]
   }
   return true, nil
}

// Decode decodes a byte slice into the Chain structure.
func (c *Chain) Decode(data []byte) error {
   n := copy(c.Magic[:], data)
   if string(c.Magic[:]) != "CHAI" {
      return errors.New("failed to find chain magic")
   }
   data = data[n:]
   c.Version = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.Length = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.Flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.CertCount = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.Certificates = make([]Certificate, c.CertCount)
   for i := range c.CertCount {
      var cert Certificate
      n, err := cert.decode(data)
      if err != nil {
         return err
      }
      c.Certificates[i] = cert
      data = data[n:]
   }
   return nil
}

type Chain struct {
   Magic        [4]byte
   Version      uint32
   Length       uint32
   Flags        uint32
   CertCount    uint32
   Certificates []Certificate
}

func (c *Chain) Encode() []byte {
   data := c.Magic[:]
   data = binary.BigEndian.AppendUint32(data, c.Version)
   data = binary.BigEndian.AppendUint32(data, c.Length)
   data = binary.BigEndian.AppendUint32(data, c.Flags)
   data = binary.BigEndian.AppendUint32(data, c.CertCount)
   for _, cert := range c.Certificates {
      data = cert.Append(data)
   }
   return data
}
