package playReady

import (
   "encoding/binary"
   "errors"
)

func (c *certificateSignature) size() int {
   n := binary.Size(c.signatureType)
   n += binary.Size(c.signatureLength)
   n += 64
   n += binary.Size(c.issuerLength)
   n += 64
   return n
}

type ftlv struct {
   Flags  uint16
   Type   uint16
   Length uint32
   Value  []byte // The raw value bytes of the FTLV object
}

type Certificate struct {
   Magic             [4]byte // bytes 0 - 3
   Version           uint32  // bytes 4 - 7
   Length            uint32  // bytes 8 - 11
   LengthToSignature uint32  // bytes 12 - 15
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

func (f *features) size() int {
   n := binary.Size(f.entries)
   for _, feature := range f.features {
      n += binary.Size(feature)
   }
   return n
}

type features struct {
   entries  uint32   // Number of feature entries
   features []uint32 // Slice of feature IDs
}

func (k *keyData) size() int {
   n := binary.Size(k.keyType)
   n += binary.Size(k.length)
   n += binary.Size(k.flags)
   n += len(k.publicKey)
   n += k.usage.size()
   return n
}

type keyData struct {
   keyType   uint16
   length    uint16 // Total length of the keyData structure
   flags     uint32
   publicKey [64]byte // ECDSA P256 public key (X and Y coordinates)
   usage     features // Features indicating key usage
}

func (k *keyInfo) size() int {
   n := binary.Size(k.entries)
   for _, key := range k.keys {
      n += key.size()
   }
   return n
}

type keyInfo struct {
   entries uint32    // Number of key entries
   keys    []keyData // Slice of keyData structures
}

func (f *ftlv) size() int {
   n := binary.Size(f.Flags)
   n += binary.Size(f.Type)
   n += binary.Size(f.Length)
   n += len(f.Value)
   return n
}

type certificateSignature struct {
   signatureType   uint16
   signatureLength uint16
   // The actual signature bytes
   SignatureData   []byte
   issuerLength    uint32
   // The public key of the issuer that signed this certificate
   IssuerKey       []byte
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

// decode decodes a byte slice into the keyData structure.
// It returns the number of bytes consumed.
func (k *keyData) decode(data []byte) int {
   k.keyType = binary.BigEndian.Uint16(data)
   n := 2
   k.length = binary.BigEndian.Uint16(data[n:])
   n += 2
   k.flags = binary.BigEndian.Uint32(data[n:])
   n += 4
   n += copy(k.publicKey[:], data[n:])
   n += k.usage.decode(data[n:])
   return n
}

// Constants for object types within the certificate structure.
const (
   objTypeBasic            = 0x0001
   objTypeDomain           = 0x0002
   objTypePc               = 0x0003
   objTypeDevice           = 0x0004
   objTypeFeature          = 0x0005
   objTypeKey              = 0x0006
   objTypeManufacturer     = 0x0007
   objTypeSignature        = 0x0008
   objTypeSilverlight      = 0x0009
   objTypeMetering         = 0x000A
   objTypeExtDataSignKey   = 0x000B
   objTypeExtDataContainer = 0x000C
   objTypeExtDataSignature = 0x000D
   objTypeExtDataHwid      = 0x000E
   objTypeServer           = 0x000F
   objTypeSecurityVersion  = 0x0010
   objTypeSecurityVersion2 = 0x0011
)

// decode decodes a byte slice into an FTLV structure.
// It returns the number of bytes consumed.
func (f *ftlv) decode(data []byte) int {
   f.Flags = binary.BigEndian.Uint16(data)
   n := 2
   f.Type = binary.BigEndian.Uint16(data[n:])
   n += 2
   f.Length = binary.BigEndian.Uint32(data[n:])
   n += 4
   // The Value slice should contain Length-8 bytes (total length minus Flags, Type, Length fields).
   // Ensure not to panic if remaining data is less than expected FTLV Value
   // length. Go's slicing will handle `data[n:][:f.Length-8]` gracefully if
   // `f.Length-8` is larger than `len(data[n:])`, taking the minimum
   // available. However, if f.Length is less than 8, f.Length-8 would be
   // negative, causing a panic. A robust implementation would check
   // f.Length >= 8 before slicing. For this request, we assume valid f.Length
   // values as per the original code's implied behavior.
   valueLen := int(f.Length - 8)
   if valueLen < 0 {
      // Handle malformed FTLV where Length is too small to contain header.
      // This should ideally be an error, but per the original function's structure,
      // we'll try to process and return bytes consumed.
      // For now, we'll just set valueLen to 0 to avoid panic if Length is less than 8.
      valueLen = 0
   }
   if valueLen > len(data[n:]) {
      // If the reported length is greater than available data, take all
      // available data.
      f.Value = data[n:]
   } else {
      f.Value = data[n:][:valueLen]
   }

   n += len(f.Value)
   return n
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
   c.SignatureData = data[:c.signatureLength] // 70 bytes total
   data = data[c.signatureLength:]
   c.issuerLength = binary.BigEndian.Uint32(data)
   data = data[4:]
   // Ensure IssuerKey is sliced to its specific length
   c.IssuerKey = data[:c.issuerLength/8]
}

