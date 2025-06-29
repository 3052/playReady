package playReady

import (
   "41.neocities.org/playReady/xml"
   "encoding/binary"
   "encoding/hex"
   "errors"
   "math/big"
)

type xmlKey struct {
   X *big.Int
   Y *big.Int
   RawX [32]byte
}

func newLa(m *xmlKey, cipherData, kid []byte) *xml.La {
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
                  CipherValue: elGamalEncrypt(m, elGamalKeyGeneration()),
               },
            },
         },
         CipherData: xml.CipherData{
            CipherValue: cipherData,
         },
      },
   }
}

func elGamalKeyGeneration() *xmlKey {
   data, _ := hex.DecodeString(wmrmPublicKey)
   var key xmlKey
   key.X = new(big.Int).SetBytes(data[:32])
   key.Y = new(big.Int).SetBytes(data[32:])
   return &key
}

type Filler byte

func (f Filler) Read(data []byte) (int, error) {
   for index := range data {
      data[index] = byte(f)
   }
   return len(data), nil
}

func (x *xmlKey) aesIv() []byte {
   return x.RawX[:16]
}

func (x *xmlKey) aesKey() []byte {
   return x.RawX[16:]
}

func (c *ContentKey) decrypt(key *big.Int, aux *AuxKeys) error {
   switch c.CipherType {
   case 3:
      messageX, _ := elGamalDecrypt(c.Value, key)
      c.Value = messageX.Bytes()
      return nil
   case 6:
      return c.scalable(key, aux)
   }
   return errors.New("cannot decrypt key")
}

func (c *ContentKey) scalable(key *big.Int, aux *AuxKeys) error {
   rootKeyInfo, leafKeys := c.Value[:144], c.Value[144:]
   rootKey := rootKeyInfo[128:]
   messageX, _ := elGamalDecrypt(rootKeyInfo[:128], key)
   decrypted := messageX.Bytes()
   var (
      ci [16]byte
      ck [16]byte
   )
   for i := range 16 {
      ci[i] = decrypted[i*2]
      ck[i] = decrypted[i*2+1]
   }
   constantZero, err := hex.DecodeString(magicConstantZero)
   if err != nil {
      return err
   }
   rgbUplinkXkey := xorKey(ck[:], constantZero)
   contentKeyPrime, err := aesEcbEncrypt(rgbUplinkXkey, ck[:])
   if err != nil {
      return err
   }
   auxKeyCalc, err := aesEcbEncrypt(aux.Keys[0].Key[:], contentKeyPrime)
   if err != nil {
      return err
   }
   oSecondaryKey, err := aesEcbEncrypt(rootKey, ck[:])
   if err != nil {
      return err
   }
   c.Value, err = aesEcbEncrypt(leafKeys, auxKeyCalc)
   if err != nil {
      return err
   }
   c.Value, err = aesEcbEncrypt(c.Value, oSecondaryKey)
   if err != nil {
      return err
   }
   return nil
}

const wmrmPublicKey = "C8B6AF16EE941AADAA5389B4AF2C10E356BE42AF175EF3FACE93254E7B0B3D9B982B27B5CB2341326E56AA857DBFD5C634CE2CF9EA74FCA8F2AF5957EFEEA562"

type ContentKey struct {
   KeyId      [16]byte
   KeyType    uint16
   CipherType uint16
   Length     uint16
   Value      []byte
}

func (e *EccKey) decode(data []byte) {
   e.Curve = binary.BigEndian.Uint16(data)
   data = data[2:]
   e.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   e.Value = data
}

type EccKey struct {
   Curve  uint16
   Length uint16
   Value  []byte
}

func (k *KeyData) decode(data []byte) int {
   k.KeyType = binary.BigEndian.Uint16(data)
   n := 2
   k.Length = binary.BigEndian.Uint16(data[n:])
   n += 2
   k.Flags = binary.BigEndian.Uint32(data[n:])
   n += 4
   n += copy(k.PublicKey[:], data[n:])
   n += k.Usage.decode(data[n:])
   return n
}

func (k *KeyData) Append(data []byte) []byte {
   data = binary.BigEndian.AppendUint16(data, k.KeyType)
   data = binary.BigEndian.AppendUint16(data, k.Length)
   data = binary.BigEndian.AppendUint32(data, k.Flags)
   data = append(data, k.PublicKey[:]...)
   return k.Usage.Append(data)
}

func (k *KeyData) New(PublicKey []byte, Type uint32) {
   k.Length = 512 // required
   copy(k.PublicKey[:], PublicKey)
   k.Usage.New(Type)
}

type KeyData struct {
   KeyType   uint16
   Length    uint16
   Flags     uint32
   PublicKey [64]byte // ECDSA P256 public key (X and Y coordinates)
   Usage     CertFeatures
}

func (k *KeyInfo) decode(data []byte) {
   k.Entries = binary.BigEndian.Uint32(data)
   data = data[4:]
   k.Keys = make([]KeyData, k.Entries)
   for i := range k.Entries {
      var key KeyData
      n := key.decode(data)
      k.Keys[i] = key
      data = data[n:] // Advance data slice for the next key
   }
}

type KeyInfo struct {
   Entries uint32 // can be 1 or 2
   Keys    []KeyData
}

func (k *KeyInfo) New(signEncryptKey []byte) {
   k.Entries = 2 // required
   k.Keys = make([]KeyData, 2)
   k.Keys[0].New(signEncryptKey, 1)
   k.Keys[1].New(signEncryptKey, 2)
}

func (k *KeyInfo) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, k.Entries)
   for _, key := range k.Keys {
      data = key.Append(data)
   }
   return data
}

func (k *KeyInfo) ftlv(Flag, Type uint16) *Ftlv {
   return newFtlv(Flag, Type, k.encode())
}

func (k *KeyInfo) size() int {
   n := 4 // entries
   for _, key := range k.Keys {
      n += key.size()
   }
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

const magicConstantZero = "7ee9ed4af773224f00b8ea7efb027cbb"

// xorKey performs XOR operation on two byte slices.
func xorKey(a, b []byte) []byte {
   if len(a) != len(b) {
      panic("slices have different lengths")
   }
   c := make([]byte, len(a))
   for i := 0; i < len(a); i++ {
      c[i] = a[i] ^ b[i]
   }
   return c
}

func (c *CertFeatures) Append(data []byte) []byte {
   data = binary.BigEndian.AppendUint32(data, c.Entries)
   for _, feature := range c.Features {
      data = binary.BigEndian.AppendUint32(data, feature)
   }
   return data
}

func (c *CertFeatures) New(Type uint32) {
   c.Entries = 1
   c.Features = []uint32{Type}
}

func (c *CertFeatures) ftlv(Flag, Type uint16) *Ftlv {
   return newFtlv(Flag, Type, c.Append(nil))
}

func (c *CertFeatures) size() int {
   n := 4 // entries
   n += 4 * len(c.Features)
   return n
}

// It returns the number of bytes consumed.
func (c *CertFeatures) decode(data []byte) int {
   c.Entries = binary.BigEndian.Uint32(data)
   n := 4
   c.Features = make([]uint32, c.Entries)
   for i := range c.Entries {
      c.Features[i] = binary.BigEndian.Uint32(data[n:])
      n += 4
   }
   return n
}

type CertFeatures struct {
   Entries  uint32
   Features []uint32
}

func (c *ContentKey) Key() []byte {
   return c.Value[16:]
}

// decode decodes a byte slice into a ContentKey structure.
func (c *ContentKey) decode(data []byte) {
   n := copy(c.KeyId[:], data)
   data = data[n:]
   c.KeyType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.CipherType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.Value = data
}

func (c *ContentKey) integrity() []byte {
   return c.Value[:16]
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

type CertificateInfo struct {
   CertificateId [16]byte
   SecurityLevel uint32
   Flags         uint32
   InfoType      uint32
   Digest        [32]byte
   Expiry        uint32
   ClientId      [16]byte // Client ID (can be used for license binding)
}

func (c *CertificateInfo) encode() []byte {
   data := c.CertificateId[:]
   data = binary.BigEndian.AppendUint32(data, c.SecurityLevel)
   data = binary.BigEndian.AppendUint32(data, c.Flags)
   data = binary.BigEndian.AppendUint32(data, c.InfoType)
   data = append(data, c.Digest[:]...)
   data = binary.BigEndian.AppendUint32(data, c.Expiry)
   return append(data, c.ClientId[:]...)
}

func (c *CertificateInfo) ftlv(Flag, Type uint16) *Ftlv {
   return newFtlv(Flag, Type, c.encode())
}

func newFtlv(Flag, Type uint16, Value []byte) *Ftlv {
   return &Ftlv{
      Flag:   Flag,
      Type:   Type,
      Length: 8 + uint32(len(Value)),
      Value:  Value,
   }
}

func (f *Ftlv) size() int {
   n := 2 // Flag
   n += 2 // Type
   n += 4 // Length
   n += len(f.Value)
   return n
}

func (f *Ftlv) Append(data []byte) []byte {
   data = binary.BigEndian.AppendUint16(data, f.Flag)
   data = binary.BigEndian.AppendUint16(data, f.Type)
   data = binary.BigEndian.AppendUint32(data, f.Length)
   return append(data, f.Value...)
}

func (k *KeyData) size() int {
   n := 2 // keyType
   n += 2 // length
   n += 4 // flags
   n += len(k.PublicKey)
   n += k.Usage.size()
   return n
}

func (l *LicenseSignature) size() int {
   n := 2 // type
   n += 2 // length
   n += len(l.Data)
   return n
}

type xmrType uint16

const (
   outerContainerEntryType                 xmrType = 1
   globalPolicyContainerEntryType          xmrType = 2
   playbackPolicyContainerEntryType        xmrType = 4
   minimumOutputProtectionLevelsEntryType  xmrType = 5
   explicitAnalogVideoProtectionEntryType  xmrType = 7
   analogVideoOPLEntryType                 xmrType = 8
   keyMaterialContainerEntryType           xmrType = 9
   contentKeyEntryType                     xmrType = 10
   signatureEntryType                      xmrType = 11
   serialNumberEntryType                   xmrType = 12
   rightsEntryType                         xmrType = 13
   expirationEntryType                     xmrType = 18
   issueDateEntryType                      xmrType = 19
   meteringEntryType                       xmrType = 22
   gracePeriodEntryType                    xmrType = 26
   sourceIdEntryType                       xmrType = 34
   restrictedSourceIdEntryType             xmrType = 40
   domainIdEntryType                       xmrType = 41
   deviceKeyEntryType                      xmrType = 42
   policyMetadataEntryType                 xmrType = 44
   optimizedContentKeyEntryType            xmrType = 45
   explicitDigitalAudioProtectionEntryType xmrType = 46
   expireAfterFirstUseEntryType            xmrType = 48
   digitalAudioOPLEntryType                xmrType = 49
   revocationInfoVersionEntryType          xmrType = 50
   embeddingBehaviorEntryType              xmrType = 51
   securityLevelEntryType                  xmrType = 52
   moveEnablerEntryType                    xmrType = 55
   uplinkKidEntryType                      xmrType = 59
   copyPoliciesContainerEntryType          xmrType = 60
   copyCountEntryType                      xmrType = 61
   removalDateEntryType                    xmrType = 80
   auxKeyEntryType                         xmrType = 81
   uplinkXEntryType                        xmrType = 82
   realTimeExpirationEntryType             xmrType = 85
   explicitDigitalVideoProtectionEntryType xmrType = 88
   digitalVideoOPLEntryType                xmrType = 89
   secureStopEntryType                     xmrType = 90
   copyUnknownObjectEntryType              xmrType = 65533
   globalPolicyUnknownObjectEntryType      xmrType = 65533
   playbackUnknownObjectEntryType          xmrType = 65533
   copyUnknownContainerEntryType           xmrType = 65534
   unknownContainersEntryType              xmrType = 65534
   playbackUnknownContainerEntryType       xmrType = 65534
)

func UuidOrGuid(data []byte) {
   // Data1 (first 4 bytes) - swap endianness in place
   data[0], data[3] = data[3], data[0]
   data[1], data[2] = data[2], data[1]
   // Data2 (next 2 bytes) - swap endianness in place
   data[4], data[5] = data[5], data[4]
   // Data3 (next 2 bytes) - swap endianness in place
   data[6], data[7] = data[7], data[6]
   // Data4 (last 8 bytes) - no change needed, so no operation here
}

func (l *License) decode(data []byte) error {
   n := copy(l.Magic[:], data)
   data = data[n:]
   l.Offset = binary.BigEndian.Uint16(data)
   data = data[2:]
   l.Version = binary.BigEndian.Uint16(data)
   data = data[2:]
   n = copy(l.RightsId[:], data)
   data = data[n:]
   var value1 Ftlv
   _, err := value1.decode(data) // Type 1
   if err != nil {
      return err
   }
   for len(value1.Value) >= 1 {
      var value2 Ftlv
      n, err = value2.decode(value1.Value)
      if err != nil {
         return err
      }
      value1.Value = value1.Value[n:]
      switch xmrType(value2.Type) {
      case globalPolicyContainerEntryType: // 2
         // Rakuten
      case playbackPolicyContainerEntryType: // 4
         // Rakuten
      case keyMaterialContainerEntryType: // 9
         for len(value2.Value) >= 1 {
            var value3 Ftlv
            n, err = value3.decode(value2.Value)
            if err != nil {
               return err
            }
            value2.Value = value2.Value[n:]
            switch xmrType(value3.Type) {
            case contentKeyEntryType: // 10
               l.ContentKey = &ContentKey{}
               l.ContentKey.decode(value3.Value)
            case deviceKeyEntryType: // 42
               l.EccKey = &EccKey{}
               l.EccKey.decode(value3.Value)
            case auxKeyEntryType: // 81
               l.AuxKeys = &AuxKeys{}
               l.AuxKeys.decode(value3.Value)
            default:
               return errors.New("Ftlv.type")
            }
         }
      case signatureEntryType: // 11
         l.Signature = &LicenseSignature{}
         l.Signature.decode(value2.Value)
      default:
         return errors.New("Ftlv.type")
      }
   }
   return nil
}

type License struct {
   Magic      [4]byte           // 0
   Offset     uint16            // 1
   Version    uint16            // 2
   RightsId   [16]byte          // 3
   ContentKey *ContentKey       // 4.9.10
   EccKey     *EccKey           // 4.9.42
   AuxKeys    *AuxKeys          // 4.9.81
   Signature  *LicenseSignature // 4.11
}

func (f *Ftlv) decode(data []byte) (int, error) {
   f.Flag = binary.BigEndian.Uint16(data)
   n := 2
   f.Type = binary.BigEndian.Uint16(data[n:])
   n += 2
   f.Length = binary.BigEndian.Uint32(data[n:])
   n += 4
   f.Value = data[n:f.Length]
   n += len(f.Value)
   return n, nil
}

type Ftlv struct {
   Flag   uint16 // this can be 0 or 1
   Type   uint16
   Length uint32
   Value  []byte
}

func (a *AuxKeys) decode(data []byte) {
   a.Count = binary.BigEndian.Uint16(data)
   data = data[2:]
   a.Keys = make([]AuxKey, a.Count)
   for i := range a.Count {
      var key AuxKey
      n := key.decode(data)
      a.Keys[i] = key
      data = data[n:]
   }
}

type AuxKeys struct {
   Count uint16
   Keys  []AuxKey
}

func (a *AuxKey) decode(data []byte) int {
   a.Location = binary.BigEndian.Uint32(data)
   n := 4
   n += copy(a.Key[:], data[n:])
   return n
}

type AuxKey struct {
   Location uint32
   Key      [16]byte
}

func (l *LicenseSignature) decode(data []byte) {
   l.Type = binary.BigEndian.Uint16(data)
   data = data[2:]
   l.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   l.Data = data
}

type LicenseSignature struct {
   Type   uint16
   Length uint16
   Data   []byte
}

func (c *CertificateInfo) decode(data []byte) {
   n := copy(c.CertificateId[:], data)
   data = data[n:]
   c.SecurityLevel = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.Flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.InfoType = binary.BigEndian.Uint32(data)
   data = data[4:]
   n = copy(c.Digest[:], data)
   data = data[n:]
   c.Expiry = binary.BigEndian.Uint32(data)
   data = data[4:]
   copy(c.ClientId[:], data)
}

func (c *CertificateInfo) New(securityLevel uint32, digest []byte) {
   copy(c.Digest[:], digest)
   // required, Max uint32, effectively never expires
   c.Expiry = 4294967295
   // required
   c.InfoType = 2
   c.SecurityLevel = securityLevel
}
