package playReady

import (
   "encoding/binary"
   "errors"
)

// Certificate represents the top-level structure of a PlayReady certificate.
type Certificate struct {
   Magic             [4]byte // "CERT" magic bytes
   Version           uint32  // Certificate version
   Length            uint32  // Total length of the certificate data
   LengthToSignature uint32  // Length from start of certificate to the signature
   certificateInfo   *certificateInfo
   keyInfo           *keyInfo
   signature         *certificateSignature
   UnhandledObjects  []ftlv // New: Stores FTLV objects for unhandled types
   
   rawData []byte
}

// decode parses the byte slice into the Certificate structure.
// It returns the number of bytes consumed and an error, if any.
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

   // Extract the raw data containing FTLV objects.
   // The Length field includes the initial 16 bytes (Magic, Version, Length, LengthToSignature).
   // So, rawData is the remaining part of the certificate content.
   c.rawData = data[n:][:c.Length-16]
   n += len(c.rawData) // Increment total bytes consumed by the rawData length

   // Initialize the slice to store unhandled FTLV objects.
   c.UnhandledObjects = []ftlv{}

   var n1 int // n1 tracks bytes consumed within rawData
   for n1 < len(c.rawData) {
      var value ftlv
      // Decode the current FTLV object.
      // ftlv.decode returns the number of bytes read for this FTLV object.
      bytesReadFromFtlv := value.decode(c.rawData[n1:])

      // Basic check to prevent infinite loops if ftlv.decode reads 0 bytes
      // but there's still data remaining. This might indicate malformed data.
      if bytesReadFromFtlv == 0 && len(c.rawData[n1:]) > 0 {
         return n, errors.New("FTLV.decode read 0 bytes but more rawData was available, potential malformed FTLV")
      }

      // Process the FTLV object based on its Type.
      switch value.Type {
      case objTypeBasic: // 0x0001
         c.certificateInfo = &certificateInfo{}
         c.certificateInfo.decode(value.Value)
      case objTypeKey: // 0x0006
         c.keyInfo = &keyInfo{}
         c.keyInfo.decode(value.Value)
      case objTypeSignature: // 0x0008
         c.signature = &certificateSignature{}
         c.signature.decode(value.Value)
      case objTypeDevice, objTypeFeature, objTypeManufacturer, objTypeDomain, objTypePc,
         objTypeSilverlight, objTypeMetering, objTypeExtDataSignKey, objTypeExtDataContainer,
         objTypeExtDataSignature, objTypeExtDataHwid, objTypeServer, objTypeSecurityVersion,
         objTypeSecurityVersion2:
         // These are known types but are currently not parsed into specific structs.
         // Save them to UnhandledObjects for later inspection or re-construction.
         c.UnhandledObjects = append(c.UnhandledObjects, value)
      default:
         // Any other unknown or unhandled object types are saved.
         c.UnhandledObjects = append(c.UnhandledObjects, value)
      }
      n1 += bytesReadFromFtlv // Move to the next FTLV object in rawData
   }
   return n, nil // Return total bytes consumed and nil for no error
}

// keyData represents a key structure within the certificate.
type keyData struct {
   keyType   uint16
   length    uint16 // Total length of the keyData structure
   flags     uint32
   publicKey [64]byte // ECDSA P256 public key (X and Y coordinates)
   usage     features // Features indicating key usage
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

// ftlv represents a general FTLV (Flags, Type, Length, Value) structure.
type ftlv struct {
   Flags  uint16
   Type   uint16
   Length uint32
   Value  []byte // The raw value bytes of the FTLV object
}

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
   // Ensure not to panic if remaining data is less than expected FTLV Value length.
   // Go's slicing will handle `data[n:][:f.Length-8]` gracefully if `f.Length-8` is larger than `len(data[n:])`,
   // taking the minimum available.
   // However, if f.Length is less than 8, f.Length-8 would be negative, causing a panic.
   // A robust implementation would check f.Length >= 8 before slicing.
   // For this request, we assume valid f.Length values as per the original code's implied behavior.
   valueLen := int(f.Length - 8)
   if valueLen < 0 {
      // Handle malformed FTLV where Length is too small to contain header.
      // This should ideally be an error, but per the original function's structure,
      // we'll try to process and return bytes consumed.
      // For now, we'll just set valueLen to 0 to avoid panic if Length is less than 8.
      valueLen = 0
   }
   if valueLen > len(data[n:]) {
      // If the reported length is greater than available data, take all available data.
      f.Value = data[n:]
   } else {
      f.Value = data[n:][:valueLen]
   }

   n += len(f.Value)
   return n
}

// certificateInfo represents basic information about the certificate.
type certificateInfo struct {
   certificateId [16]byte
   securityLevel uint32
   flags         uint32
   infoType      uint32
   digest        [32]byte
   expiry        uint32
   clientId      [16]byte // Client ID (can be used for license binding)
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

// features represents a list of features.
type features struct {
   entries  uint32   // Number of feature entries
   features []uint32 // Slice of feature IDs
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

// keyInfo represents a collection of key data.
type keyInfo struct {
   entries uint32    // Number of key entries
   keys    []keyData // Slice of keyData structures
}

// decode decodes a byte slice into the keyInfo structure.
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

// certificateSignature represents the signature block of the certificate.
type certificateSignature struct {
   signatureType   uint16
   signatureLength uint16
   SignatureData   []byte // The actual signature bytes
   issuerLength    uint32
   IssuerKey       []byte // The public key of the issuer that signed this certificate
}

// decode decodes a byte slice into the certificateSignature structure.
func (c *certificateSignature) decode(data []byte) {
   c.signatureType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.signatureLength = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.SignatureData = data[:c.signatureLength]
   data = data[c.signatureLength:]
   c.issuerLength = binary.BigEndian.Uint32(data)
   data = data[4:]
   // Ensure IssuerKey is sliced to its specific length
   c.IssuerKey = data[:c.issuerLength/8]
}
