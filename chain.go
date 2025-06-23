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

func (c *Certificate) size() (uint32, uint32) {
   n := len(c.Magic)
   n += 4 // Version
   n += 4 // Length
   n += 4 // LengthToSignature
   if c.certificateInfo != nil {
      n += new(ftlv).size()
      n += binary.Size(c.certificateInfo)
   }
   if c.feature != nil {
      n += c.feature.size()
   }
   if c.keyInfo != nil {
      n += new(ftlv).size()
      n += c.keyInfo.size()
   }
   if c.manufacturer != nil {
      n += c.manufacturer.size()
   }
   n1 := n
   n1 += new(ftlv).size()
   n1 += c.signature.size()
   return uint32(n), uint32(n1)
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
   signature, err := sign(signEncrypt[0], signedDigest[:])
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

type Chain struct {
   Magic     [4]byte
   Version   uint32
   Length    uint32
   Flags     uint32
   CertCount uint32
   Certs     []Certificate
}

func (c *Chain) Encode() []byte {
   data := c.Magic[:]
   data = binary.BigEndian.AppendUint32(data, c.Version)
   data = binary.BigEndian.AppendUint32(data, c.Length)
   data = binary.BigEndian.AppendUint32(data, c.Flags)
   data = binary.BigEndian.AppendUint32(data, c.CertCount)
   for _, cert := range c.Certs {
      data = cert.Append(data)
   }
   return data
}

type certificateSignature struct {
   signatureType   uint16
   signatureLength uint16
   // The actual signature bytes
   signature    []byte
   issuerLength uint32
   // The public key of the issuer that signed this certificate
   IssuerKey []byte
}

func (c *certificateSignature) size() int {
   n := 2  // signatureType
   n += 2  // signatureLength
   n += 64 // signature
   n += 4  // issuerLength
   n += 64 // issuerKey
   return n
}

func (c *certificateSignature) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, c.signatureType)
   data = binary.BigEndian.AppendUint16(data, c.signatureLength)
   data = append(data, c.signature...)
   data = binary.BigEndian.AppendUint32(data, c.issuerLength)
   return append(data, c.IssuerKey...)
}

func (c *certificateSignature) New(signature, modelKey []byte) error {
   c.signatureType = 1 // required
   c.signatureLength = 64
   if len(signature) != 64 {
      return errors.New("signature length invalid")
   }
   c.signature = signature
   c.issuerLength = 512
   if len(modelKey) != 64 {
      return errors.New("model key length invalid")
   }
   c.IssuerKey = modelKey
   return nil
}

func (c *certificateSignature) decode(data []byte) error {
   c.signatureType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.signatureLength = binary.BigEndian.Uint16(data)
   if c.signatureLength != 64 {
      return errors.New("signature length invalid")
   }
   data = data[2:]
   c.signature = data[:c.signatureLength]
   data = data[c.signatureLength:]
   c.issuerLength = binary.BigEndian.Uint32(data)
   if c.issuerLength != 512 {
      return errors.New("issuer length invalid")
   }
   data = data[4:]
   c.IssuerKey = data[:c.issuerLength/8]
   return nil
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
      var value ftlv
      bytesReadFromFtlv, err := value.decode(data[n:])
      if err != nil {
         return 0, err
      }
      switch value.Type {
      case objTypeBasic: // 0x0001
         c.certificateInfo = &certificateInfo{}
         c.certificateInfo.decode(value.Value)
      case objTypeFeature: // 0x0005
         c.feature = &value
      case objTypeKey: // 0x0006
         c.keyInfo = &keyInfo{}
         c.keyInfo.decode(value.Value)
      case objTypeManufacturer: // 0x0007
         c.manufacturer = &value
      case objTypeSignature: // 0x0008
         c.signature = &certificateSignature{}
         err := c.signature.decode(value.Value)
         if err != nil {
            return 0, err
         }
      default:
         return 0, errors.New("ftlv.Type")
      }
      n += bytesReadFromFtlv
   }
   return n, nil // Return total bytes consumed and nil for no error
}

type Certificate struct {
   Magic             [4]byte               // bytes 0 - 3
   Version           uint32                // bytes 4 - 7
   Length            uint32                // bytes 8 - 11
   LengthToSignature uint32                // bytes 12 - 15
   certificateInfo   *certificateInfo      // type 1
   feature           *ftlv                 // type 5
   keyInfo           *keyInfo              // type 6
   manufacturer      *ftlv                 // type 7
   signature         *certificateSignature // type 8
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
   data := c.Append(nil)
   data = data[:c.LengthToSignature]
   signatureDigest := sha256.Sum256(data)
   signature := c.signature.signature
   r := new(big.Int).SetBytes(signature[:32])
   s := new(big.Int).SetBytes(signature[32:])
   return ecdsa.Verify(&publicKey, signatureDigest[:], r, s)
}

///

func (c *Chain) Leaf(modelKey, signEncryptKey *EcKey) error {
   if !bytes.Equal(c.Certs[0].keyInfo.keys[0].publicKey[:], modelKey.public()) {
      return errors.New("zgpriv not for cert")
   }
   if !c.verify() {
      return errors.New("cert is not valid")
   }
   var cert Certificate
   copy(cert.Magic[:], "CERT")
   cert.Version = 1 // required
   // SCALABLE with SL2000, SUPPORTS_PR3_FEATURES
   cert.feature = newFeatures(0xD).ftlv(0, 5)
   cert.keyInfo = newKeyInfo(signEncryptKey.public())
   {
      sum := sha256.Sum256(signEncryptKey.public())
      cert.certificateInfo = c.Certs[0].certificateInfo.New(sum[:])
   }
   {
      cert.LengthToSignature, cert.Length = cert.size()
      sum := sha256.Sum256(cert.Append(nil))
      signature, err := sign(modelKey[0], sum[:])
      if err != nil {
         return err
      }
      var value certificateSignature
      err = value.New(signature, modelKey.public())
      if err != nil {
         return err
      }
      cert.signature = &value
   }
   c.CertCount += 1
   c.Certs = slices.Insert(c.Certs, 0, cert)
   c.Length += cert.Length
   return nil
}

func (c *Certificate) Append(data []byte) []byte {
   data = append(data, c.Magic[:]...)
   data = binary.BigEndian.AppendUint32(data, c.Version)
   data = binary.BigEndian.AppendUint32(data, c.Length)
   data = binary.BigEndian.AppendUint32(data, c.LengthToSignature)
   if c.certificateInfo != nil {
      data = c.certificateInfo.ftlv(1, 1).Append(data)
   }
   if c.feature != nil {
      data = c.feature.Append(data)
   }
   if c.keyInfo != nil {
      // data = c.keyInfo.ftlv(1, 6).Append(data)
      data1 := c.keyInfo.encode()
      value := ftlv{
         Flag:  1,
         Type:  6,
         Length: uint32(len(data1)) + 8,
         Value: data1,
      }
      data = value.Append(data)
   }
   if c.manufacturer != nil {
      data = c.manufacturer.Append(data)
   }
   if c.signature != nil {
      data1 := c.signature.encode()
      value := ftlv{
         Type:  8,
         Length: uint32(len(data1)) + 8,
         Value: data1,
      }
      data = value.Append(data)
   }
   return data
}
