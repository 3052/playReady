package playReady

import (
   "41.neocities.org/playReady/xml"
   "bytes"
   "crypto/ecdsa"
   "crypto/sha256"
   "encoding/binary"
   "errors"
   "slices"
)

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

// Encode encodes the Chain into a byte slice.
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

type Chain struct {
   Magic     [4]byte
   Version   uint32
   Length    uint32
   Flags     uint32
   CertCount uint32
   Certs     []Certificate
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

func (c *Chain) Leaf(modelKey, signEncryptKey *EcKey) error {
   if !bytes.Equal(c.Certs[0].keyInfo.keys[0].publicKey[:], modelKey.Public()) {
      return errors.New("zgpriv not for cert")
   }
   // Verify the existing chain's validity.
   if !c.verify() {
      return errors.New("cert is not valid")
   }
   var leafData bytes.Buffer
   {
      digest := sha256.Sum256(signEncryptKey.Public())
      var data certificateInfo
      data.New(c.Certs[0].certificateInfo.securityLevel, digest[:])
      var value ftlv
      value.New(1, 1, data.encode())
      leafData.Write(value.encode())
   }
   {
      // Create a new device and its FTLV.
      var data device
      data.New()
      var value ftlv
      value.New(1, 4, data.encode())
      leafData.Write(value.encode())
   }
   {
      // SCALABLE with SL2000, SUPPORTS_PR3_FEATURES
      data := features{
         entries:  1,
         features: []uint32{0xD},
      }
      // Create FTLV for features.
      var value ftlv
      value.New(1, 5, data.encode())
      leafData.Write(value.encode())
   }
   {
      var data keyInfo
      data.New(signEncryptKey.Public())
      var value ftlv
      value.New(1, 6, data.encode())
      leafData.Write(value.encode())
   }
   {
      // Create FTLV for manufacturer information, copying from the existing
      // chain's first cert.
      var value ftlv
      value.New(0, 7, c.Certs[0].manufacturerInfo.encode())
      leafData.Write(value.encode())
   }
   var unsigned Certificate
   unsigned.newNoSig(leafData.Bytes())
   {
      digest := sha256.Sum256(unsigned.encode())
      r, s, err := ecdsa.Sign(Fill('A'), modelKey[0], digest[:])
      if err != nil {
         return err
      }
      var data certificateSignature
      data.New(append(r.Bytes(), s.Bytes()...), modelKey.Public())
      var value ftlv
      value.New(1, 8, data.encode())
      leafData.Write(value.encode())
   }
   unsigned.Length = uint32(leafData.Len()) + 16
   unsigned.rawData = leafData.Bytes()
   c.Length += unsigned.Length
   c.CertCount += 1
   c.Certs = slices.Insert(c.Certs, 0, unsigned)
   return nil
}
