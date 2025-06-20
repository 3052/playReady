package playReady

import (
   "41.neocities.org/playReady/xml"
   "bytes"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/sha256"
   "encoding/binary"
   "errors"
   "math/big"
   "slices"
)

func (c *Chain) Leaf(modelKey, signEncryptKey *EcKey) error {
   if !bytes.Equal(c.Certs[0].keyInfo.keys[0].publicKey[:], modelKey.public()) {
      return errors.New("zgpriv not for cert")
   }
   if !c.verify() {
      return errors.New("cert is not valid")
   }
   var cert Certificate
   copy(cert.Magic[:], "CERT")
   cert.Version = 1
   {
      sum := sha256.Sum256(signEncryptKey.public())
      var value certificateInfo
      value.New(c.Certs[0].certificateInfo.securityLevel, sum[:])
      cert.certificateInfo = &value
   }
   {
      // SCALABLE with SL2000, SUPPORTS_PR3_FEATURES
      var data features
      data.New(0xD)
      var value ftlv
      value.New(1, 5, data.encode())
      cert.feature = &value
   }
   {
      var value keyInfo
      value.New(signEncryptKey.public())
      cert.keyInfo = &value
   }
   {
      var value certificateSignature
      cert.LengthToSignature = uint32(cert.size())
      cert.Length = cert.LengthToSignature
      cert.Length += uint32(new(ftlv).size())
      cert.Length += uint32(value.size())
      sum := sha256.Sum256(cert.encode())
      r, s, err := ecdsa.Sign(Fill('A'), modelKey[0], sum[:])
      if err != nil {
         return err
      }
      value.New(append(r.Bytes(), s.Bytes()...), modelKey.public())
      cert.signature = &value
   }
   c.CertCount += 1
   c.Certs = slices.Insert(c.Certs, 0, cert)
   c.Length += cert.Length
   return nil
}

func (c *Certificate) encode() []byte {
   data := c.Magic[:]
   data = binary.BigEndian.AppendUint32(data, c.Version)
   data = binary.BigEndian.AppendUint32(data, c.Length)
   data = binary.BigEndian.AppendUint32(data, c.LengthToSignature)
   if c.certificateInfo != nil {
      var value ftlv
      value.New(1, 1, c.certificateInfo.encode())
      data = append(data, value.encode()...)
   }
   if c.feature != nil {
      data = append(data, c.feature.encode()...)
   }
   if c.keyInfo != nil {
      var value ftlv
      value.New(1, 6, c.keyInfo.encode())
      data = append(data, value.encode()...)
   }
   if c.manufacturer != nil {
      data = append(data, c.manufacturer.encode()...)
   }
   if c.signature != nil {
      var value ftlv
      value.New(1, 8, c.signature.encode())
      data = append(data, value.encode()...)
   }
   return data
}

func (c *Chain) cipherData(key *xmlKey) ([]byte, error) {
   data := xml.Data{
      CertificateChains: xml.CertificateChains{
         CertificateChain: c.Encode(),
      },
      Features: xml.Features{
         Feature: xml.Feature{"AESCBC"}, // SCALABLE
      },
   }
   data1, err := data.Marshal()
   if err != nil {
      return nil, err
   }
   data1, err = aesCBCHandler(data1, key.aesKey(), key.aesIv(), true)
   if err != nil {
      return nil, err
   }
   return append(key.aesIv(), data1...), nil
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
   c.Certs = make([]Certificate, c.CertCount)
   for i := range c.CertCount {
      var cert Certificate
      n, err := cert.decode(data)
      if err != nil {
         return err
      }
      c.Certs[i] = cert
      data = data[n:]
   }
   return nil
}

func (c *Chain) RequestBody(signEncrypt EcKey, kid []byte) ([]byte, error) {
   var key xmlKey
   key.New()
   cipherData, err := c.cipherData(&key)
   if err != nil {
      return nil, err
   }
   la := newLa(&key.PublicKey, cipherData, kid)
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
   signedDigest := sha256.Sum256(signedData)
   r, s, err := ecdsa.Sign(Fill('B'), signEncrypt[0], signedDigest[:])
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
                     SignatureValue: append(r.Bytes(), s.Bytes()...),
                  },
               },
            },
         },
      },
   }
   return envelope.Marshal()
}

func (c *Certificate) verify(pubKey []byte) bool {
   if !bytes.Equal(c.signature.IssuerKey, pubKey) {
      return false
   }
   // Reconstruct the ECDSA public key from the byte slice.
   publicKey := ecdsa.PublicKey{
      Curve: elliptic.P256(), // Assuming P256 curve
      X:     new(big.Int).SetBytes(pubKey[:32]),
      Y:     new(big.Int).SetBytes(pubKey[32:]),
   }
   data := c.encode()
   data = data[:c.LengthToSignature]
   signatureDigest := sha256.Sum256(data)
   signature := c.signature.SignatureData
   r := new(big.Int).SetBytes(signature[:32])
   s := new(big.Int).SetBytes(signature[32:])
   return ecdsa.Verify(&publicKey, signatureDigest[:], r, s)
}

func (c *Chain) verify() bool {
   modelBase := c.Certs[len(c.Certs)-1].signature.IssuerKey
   for i := len(c.Certs) - 1; i >= 0; i-- {
      valid := c.Certs[i].verify(modelBase[:])
      if !valid {
         return false
      }
      modelBase = c.Certs[i].keyInfo.keys[0].publicKey[:]
   }
   return true
}

func (c *Chain) Encode() []byte {
   data := c.Magic[:]
   data = binary.BigEndian.AppendUint32(data, c.Version)
   data = binary.BigEndian.AppendUint32(data, c.Length)
   data = binary.BigEndian.AppendUint32(data, c.Flags)
   data = binary.BigEndian.AppendUint32(data, c.CertCount)
   for _, cert := range c.Certs {
      data = append(data, cert.encode()...)
   }
   return data
}

type Chain struct {
   Magic     [4]byte
   Version   uint32
   Length    uint32
   Flags     uint32
   CertCount uint32
   Certs     []Certificate
}
