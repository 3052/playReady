package playReady

import (
   "41.neocities.org/playReady/xml"
   "bytes"
   "crypto/aes"
   "crypto/cipher"
   "crypto/sha256"
   "encoding/binary"
   "errors"
   "github.com/emmansun/gmsm/padding"
   "slices"
)

func (c *Chain) RequestBody(signEncrypt *EcKey, kid []byte) ([]byte, error) {
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
   signature, err := sign(&signEncrypt[0], signedDigest[:])
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
func (c *CertSignature) decode(data []byte) error {
   c.SignatureType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.SignatureLength = binary.BigEndian.Uint16(data)
   if c.SignatureLength != 64 {
      return errors.New("signature length invalid")
   }
   data = data[2:]
   c.Signature = data[:c.SignatureLength]
   data = data[c.SignatureLength:]
   c.IssuerLength = binary.BigEndian.Uint32(data)
   if c.IssuerLength != 512 {
      return errors.New("issuer length invalid")
   }
   data = data[4:]
   c.IssuerKey = data[:c.IssuerLength/8]
   return nil
}

type CertSignature struct {
   SignatureType   uint16
   SignatureLength uint16
   // The actual signature bytes
   Signature    []byte
   IssuerLength uint32
   // The public key of the issuer that signed this certificate
   IssuerKey []byte
}

func (c *CertSignature) New(signature, modelKey []byte) error {
   c.SignatureType = 1 // required
   c.SignatureLength = 64
   if len(signature) != 64 {
      return errors.New("signature length invalid")
   }
   c.Signature = signature
   c.IssuerLength = 512
   if len(modelKey) != 64 {
      return errors.New("model key length invalid")
   }
   c.IssuerKey = modelKey
   return nil
}

func (c *CertSignature) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, c.SignatureType)
   data = binary.BigEndian.AppendUint16(data, c.SignatureLength)
   data = append(data, c.Signature...)
   data = binary.BigEndian.AppendUint32(data, c.IssuerLength)
   return append(data, c.IssuerKey...)
}

func (c *CertSignature) ftlv(Flag, Type uint16) *Ftlv {
   return newFtlv(Flag, Type, c.encode())
}

func (c *CertSignature) size() int {
   n := 2  // signatureType
   n += 2  // signatureLength
   n += 64 // signature
   n += 4  // issuerLength
   n += 64 // issuerKey
   return n
}

func (c *Certificate) decode(data []byte) (int, error) {
   // Copy the magic bytes and check for "CERT" signature.
   n := copy(c.Magic[:], data)
   if string(c.Magic[:]) != "CERT" {
      return 0, errors.New("failed to find cert magic")
   }
   // Decode Version, Length, and LengthToSignature fields.
   c.Version = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.Length = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.LengthToSignature = binary.BigEndian.Uint32(data[n:])
   n += 4
   for n < int(c.Length) {
      var value Ftlv
      bytesReadFromFtlv, err := value.decode(data[n:])
      if err != nil {
         return 0, err
      }
      switch value.Type {
      case objTypeBasic: // 0x0001
         c.Info = &CertificateInfo{}
         c.Info.decode(value.Value)
      case objTypeFeature: // 0x0005
         c.Features = &value
      case objTypeKey: // 0x0006
         c.KeyInfo = &KeyInfo{}
         c.KeyInfo.decode(value.Value)
      case objTypeManufacturer: // 0x0007
         c.Manufacturer = &value
      case objTypeSignature: // 0x0008
         c.Signature = &CertSignature{}
         err := c.Signature.decode(value.Value)
         if err != nil {
            return 0, err
         }
      default:
         return 0, errors.New("Ftlv.Type")
      }
      n += bytesReadFromFtlv
   }
   return n, nil // Return total bytes consumed and nil for no error
}

type Certificate struct {
   Magic             [4]byte          // bytes 0 - 3
   Version           uint32           // bytes 4 - 7
   Length            uint32           // bytes 8 - 11
   LengthToSignature uint32           // bytes 12 - 15
   Info              *CertificateInfo // type 1
   Features          *Ftlv            // type 5
   KeyInfo           *KeyInfo         // type 6
   Manufacturer      *Ftlv            // type 7
   Signature         *CertSignature   // type 8
}

func (c *Certificate) Append(data []byte) []byte {
   data = append(data, c.Magic[:]...)
   data = binary.BigEndian.AppendUint32(data, c.Version)
   data = binary.BigEndian.AppendUint32(data, c.Length)
   data = binary.BigEndian.AppendUint32(data, c.LengthToSignature)
   if c.Info != nil {
      data = c.Info.ftlv(1, 1).Append(data)
   }
   if c.Features != nil {
      data = c.Features.Append(data)
   }
   if c.KeyInfo != nil {
      data = c.KeyInfo.ftlv(1, 6).Append(data)
   }
   if c.Manufacturer != nil {
      data = c.Manufacturer.Append(data)
   }
   if c.Signature != nil {
      data = c.Signature.ftlv(0, 8).Append(data)
   }
   return data
}

func (c *Certificate) size() (uint32, uint32) {
   n := len(c.Magic)
   n += 4 // Version
   n += 4 // Length
   n += 4 // LengthToSignature
   if c.Info != nil {
      n += new(Ftlv).size()
      n += binary.Size(c.Info)
   }
   if c.Features != nil {
      n += c.Features.size()
   }
   if c.KeyInfo != nil {
      n += new(Ftlv).size()
      n += c.KeyInfo.size()
   }
   if c.Manufacturer != nil {
      n += c.Manufacturer.size()
   }
   n1 := n
   n1 += new(Ftlv).size()
   n1 += c.Signature.size()
   return uint32(n), uint32(n1)
}

func (c *Chain) verify() bool {
   modelBase := c.Certificates[c.CertCount-1].Signature.IssuerKey
   for i := len(c.Certificates) - 1; i >= 0; i-- {
      valid := c.Certificates[i].verify(modelBase[:])
      if !valid {
         return false
      }
      modelBase = c.Certificates[i].KeyInfo.Keys[0].PublicKey[:]
   }
   return true
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

func (c *Chain) Leaf(modelKey, signEncryptKey *EcKey) error {
   if !bytes.Equal(
      c.Certificates[0].KeyInfo.Keys[0].PublicKey[:], modelKey.public(),
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
      sum := sha256.Sum256(signEncryptKey.public())
      cert.Info = &CertificateInfo{}
      cert.Info.New(c.Certificates[0].Info.SecurityLevel, sum[:])
   }
   cert.KeyInfo = &KeyInfo{}
   cert.KeyInfo.New(signEncryptKey.public())
   {
      cert.LengthToSignature, cert.Length = cert.size()
      sum := sha256.Sum256(cert.Append(nil))
      signature, err := sign(&modelKey[0], sum[:])
      if err != nil {
         return err
      }
      cert.Signature = &CertSignature{}
      err = cert.Signature.New(signature, modelKey.public())
      if err != nil {
         return err
      }
   }
   c.CertCount += 1
   c.Certificates = slices.Insert(c.Certificates, 0, cert)
   c.Length += cert.Length
   return nil
}

func (c *Chain) cipherData(key *xmlKey) ([]byte, error) {
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
   block, err := aes.NewCipher(key.aesKey())
   if err != nil {
      return nil, err
   }
   cipher.NewCBCEncrypter(block, key.aesIv()).CryptBlocks(data, data)
   return append(key.aesIv(), data...), nil
}

