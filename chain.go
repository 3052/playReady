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

func (c *certificateSignature) New(signature, modelKey []byte) {
   c.signatureType = 1
   c.signatureLength = uint16(len(signature))
   c.signature = signature
   c.issuerLength = uint32(len(modelKey)) * 8
   c.IssuerKey = modelKey
}

func (c *certificateSignature) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, c.signatureType)
   data = binary.BigEndian.AppendUint16(data, c.signatureLength)
   data = append(data, c.signature...)
   data = binary.BigEndian.AppendUint32(data, c.issuerLength)
   data = append(data, c.IssuerKey...)
   return data
}

func (c *certificateSignature) size() int {
   n := binary.Size(c.signatureType)
   n += binary.Size(c.signatureLength)
   n += 64
   n += binary.Size(c.issuerLength)
   n += 64
   return n
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
   signature := c.signature.signature
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

func (c *Certificate) size() int {
   n := len(c.Magic)
   n += binary.Size(c.Version)
   n += binary.Size(c.Length)
   n += binary.Size(c.LengthToSignature)
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
   return n
}

// decode parses the byte slice into the Certificate structure. It returns the
// number of bytes consumed and an error, if any.
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
   rawData := data[n:][:c.Length-16]
   n += len(rawData) // Increment total bytes consumed by the rawData length
   // Initialize the slice to store unhandled FTLV objects.
   var n1 int // n1 tracks bytes consumed within rawData
   for n1 < len(rawData) {
      var value ftlv
      // Decode the current FTLV object.
      // ftlv.decode returns the number of bytes read for this FTLV object.
      bytesReadFromFtlv := value.decode(rawData[n1:])
      if bytesReadFromFtlv == 0 && len(rawData[n1:]) > 0 {
         return n, errors.New("FTLV.decode read 0 bytes but more rawData was available, potential malformed FTLV")
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
         c.signature.decode(value.Value)
      default:
         return 0, errors.New("FTLV.Type")
      }
      n1 += bytesReadFromFtlv // Move to the next FTLV object in rawData
   }
   return n, nil // Return total bytes consumed and nil for no error
}

// decode decodes a byte slice into the certificateInfo structure.
func (c *certificateInfo) decode(data []byte) {
   n := copy(c.certificateId[:], data)
   data = data[n:]
   c.securityLevel = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.infoType = binary.BigEndian.Uint32(data)
   data = data[4:]
   n = copy(c.digest[:], data)
   data = data[n:]
   c.expiry = binary.BigEndian.Uint32(data)
   data = data[4:]
   copy(c.clientId[:], data)
}

// decode decodes a byte slice into the features structure.
// It returns the number of bytes consumed.
func (f *features) decode(data []byte) int {
   f.entries = binary.BigEndian.Uint32(data)
   n := 4
   f.features = make([]uint32, f.entries)
   for i := range f.entries { // Correctly iterate up to f.entries
      f.features[i] = binary.BigEndian.Uint32(data[n:])
      n += 4
   }
   return n
}

func (k *keyInfo) decode(data []byte) {
   k.entries = binary.BigEndian.Uint32(data)
   data = data[4:]
   k.keys = make([]keyData, k.entries)
   for i := range k.entries { // Correctly iterate up to k.entries
      var key keyData
      n := key.decode(data) // Decode each keyData object
      k.keys[i] = key
      data = data[n:] // Advance data slice for the next key
   }
}

type certificateInfo struct {
   certificateId [16]byte
   securityLevel uint32
   flags         uint32
   infoType      uint32
   digest        [32]byte
   expiry        uint32
   clientId      [16]byte // Client ID (can be used for license binding)
}

func (c *certificateSignature) decode(data []byte) {
   c.signatureType = binary.BigEndian.Uint16(data) // 0x1 2 bytes total
   data = data[2:]
   c.signatureLength = binary.BigEndian.Uint16(data) // 0x40 (64) 4 bytes total
   data = data[2:]
   c.signature = data[:c.signatureLength] // 70 bytes total
   data = data[c.signatureLength:]
   c.issuerLength = binary.BigEndian.Uint32(data)
   data = data[4:]
   // Ensure IssuerKey is sliced to its specific length
   c.IssuerKey = data[:c.issuerLength/8]
}
