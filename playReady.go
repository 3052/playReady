package playReady

import (
   "41.neocities.org/playReady/xml"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/sha256"
   "encoding/binary"
   "encoding/hex"
   "github.com/deatil/go-cryptobin/cryptobin/crypto"
   "math/big"
   "slices"
)

func (c *Chain) requestBody(signing EcKey, kid string) ([]byte, error) {
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
   r, s, err := ecdsa.Sign(Fill('B'), signing[0], signedDigest[:])
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

// device represents device capabilities.
type device struct {
   maxLicenseSize       uint32
   maxHeaderSize        uint32
   maxLicenseChainDepth uint32
}

// new initializes default device capabilities.
func (d *device) New() {
   d.maxLicenseSize = 10240
   d.maxHeaderSize = 15360
   d.maxLicenseChainDepth = 2
}

// encode encodes device capabilities into a byte slice.
func (d *device) encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, d.maxLicenseSize)
   data = binary.BigEndian.AppendUint32(data, d.maxHeaderSize)
   return binary.BigEndian.AppendUint32(data, d.maxLicenseChainDepth)
}

// aesECBHandler performs AES ECB encryption/decryption.
// Encrypts if encrypt is true, decrypts otherwise.
func aesECBHandler(data, key []byte, encrypt bool) ([]byte, error) {
   if encrypt {
      bin := crypto.FromBytes(data).WithKey(key).
         Aes().ECB().NoPadding().Encrypt()
      return bin.ToBytes(), bin.Error()
   } else {
      bin := crypto.FromBytes(data).WithKey(key).
         Aes().ECB().NoPadding().Decrypt()
      return bin.ToBytes(), bin.Error()
   }
}

// aesCBCHandler performs AES CBC encryption/decryption with PKCS7 padding.
// Encrypts if encrypt is true, decrypts otherwise.
func aesCBCHandler(data, key, iv []byte, encrypt bool) ([]byte, error) {
   if encrypt {
      bin := crypto.FromBytes(data).WithKey(key).WithIv(iv).
         Aes().CBC().PKCS7Padding().Encrypt()
      return bin.ToBytes(), bin.Error()
   } else {
      bin := crypto.FromBytes(data).WithKey(key).WithIv(iv).
         Aes().CBC().PKCS7Padding().Decrypt()
      return bin.ToBytes(), bin.Error()
   }
}

// newLa creates a new XML License Acquisition structure.
func newLa(m *ecdsa.PublicKey, cipherData []byte, kid string) xml.La {
   return xml.La{
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

func (f Fill) Read(data []byte) (int, error) {
   for index := range data {
      data[index] = byte(f)
   }
   return len(data), nil
}

// UUID returns the GUID as a big-endian UUID byte slice.
func (g *GUID) UUID() []byte {
   data := binary.BigEndian.AppendUint32(nil, g.Data1)
   data = binary.BigEndian.AppendUint16(data, g.Data2)
   data = binary.BigEndian.AppendUint16(data, g.Data3)
   return binary.BigEndian.AppendUint64(data, g.Data4)
}

// GUID returns the GUID as a mixed-endian GUID byte slice (standard PlayReady format).
func (g *GUID) GUID() []byte {
   data := binary.LittleEndian.AppendUint32(nil, g.Data1)
   data = binary.LittleEndian.AppendUint16(data, g.Data2)
   data = binary.LittleEndian.AppendUint16(data, g.Data3)
   return binary.BigEndian.AppendUint64(data, g.Data4)
}

// Decode decodes a byte slice into a GUID structure.
func (g *GUID) Decode(data []byte) {
   g.Data1 = binary.LittleEndian.Uint32(data)
   data = data[4:]
   g.Data2 = binary.LittleEndian.Uint16(data)
   data = data[2:]
   g.Data3 = binary.LittleEndian.Uint16(data)
   data = data[2:]
   g.Data4 = binary.BigEndian.Uint64(data)
}

// Decode decodes a byte slice into an AuxKey structure.
func (a *auxKey) decode(data []byte) int {
   a.Location = binary.BigEndian.Uint32(data)
   n := 4
   n += copy(a.Key[:], data[n:])
   return n
}

// Decode decodes a byte slice into an AuxKeys structure.
func (a *auxKeys) decode(data []byte) {
   a.Count = binary.BigEndian.Uint16(data)
   data = data[2:]
   for range a.Count {
      var key auxKey
      n := key.decode(data)
      a.Keys = append(a.Keys, key)
      data = data[n:]
   }
}

// Encode encodes an FTLV structure into a byte slice.
func (f *ftlv) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, f.Flags)
   data = binary.BigEndian.AppendUint16(data, f.Type)
   data = binary.BigEndian.AppendUint32(data, f.Length)
   return append(data, f.Value...)
}

// Decode decodes a byte slice into an FTLV structure.
func (f *ftlv) decode(data []byte) int {
   f.Flags = binary.BigEndian.Uint16(data)
   n := 2
   f.Type = binary.BigEndian.Uint16(data[n:])
   n += 2
   f.Length = binary.BigEndian.Uint32(data[n:])
   n += 4
   f.Value = data[n:][:f.Length-8]
   n += int(f.Length) - 8
   return n
}

// New initializes an FTLV structure.
func (f *ftlv) New(flags, Type int, value []byte) {
   f.Flags = uint16(flags)
   f.Type = uint16(Type)
   f.Length = uint32(len(value) + 8)
   f.Value = value
}

// decode decodes a byte slice into a Signature structure.
func (s *signature) decode(data []byte) {
   s.Type = binary.BigEndian.Uint16(data)
   data = data[2:]
   s.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   s.Data = data
}

// ecdsaSignature represents an ECDSA signature structure within a certificate.
type ecdsaSignature struct {
   signatureType   uint16
   signatureLength uint16
   SignatureData   []byte // The actual signature bytes
   issuerLength    uint32
   IssuerKey       []byte // The public key of the issuer that signed this
}

// Encode encodes the ecdsaSignature into a byte slice.
func (s *ecdsaSignature) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, s.signatureType)
   data = binary.BigEndian.AppendUint16(data, s.signatureLength)
   data = append(data, s.SignatureData...)
   // The original code multiplied issuerLength by 8, implying a bit length,
   // but the IssuerKey length is in bytes. Assuming this multiplication
   // is specific to how it was serialized for a purpose external to this data structure itself.
   data = binary.BigEndian.AppendUint32(data, s.issuerLength*8)
   return append(data, s.IssuerKey...)
}

// New initializes a new ecdsaSignature with provided signature data and signing key.
func (s *ecdsaSignature) New(signatureData, signingKey []byte) {
   s.signatureType = 1
   s.signatureLength = uint16(len(signatureData))
   s.SignatureData = signatureData
   s.issuerLength = uint32(len(signingKey))
   s.IssuerKey = signingKey
}

// Decode decodes a byte slice into the ecdsaSignature structure.
func (s *ecdsaSignature) decode(data []byte) {
   s.signatureType = binary.BigEndian.Uint16(data)
   data = data[2:]
   s.signatureLength = binary.BigEndian.Uint16(data)
   data = data[2:]
   s.SignatureData = data[:s.signatureLength]
   data = data[s.signatureLength:]
   s.issuerLength = binary.BigEndian.Uint32(data)
   data = data[4:]
   s.IssuerKey = data[:s.issuerLength/8] // Divide by 8 as issuerLength was multiplied by 8 during encode
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

// manufacturerInfo contains a length-prefixed string. Renamed to avoid conflict.
type manufacturerInfo struct {
   length uint32
   value  string
}

// encode encodes the manufacturerInfo structure into a byte slice.
func (m *manufacturerInfo) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, m.length)
   return append(data, []byte(m.value)...)
}

// decode decodes a byte slice into the manufacturerInfo structure.
func (m *manufacturerInfo) decode(data []byte) int {
   m.length = binary.BigEndian.Uint32(data)
   n := 4
   // Data is padded to a multiple of 4 bytes.
   padded_length := (m.length + 3) &^ 3
   m.value = string(data[n:][:padded_length])
   n += int(padded_length)
   return n
}

// manufacturer represents manufacturer details. Renamed to avoid conflict.
type manufacturer struct {
   flags            uint32
   manufacturerName manufacturerInfo
   modelName        manufacturerInfo
   modelNumber      manufacturerInfo
}

// encode encodes the manufacturer structure into a byte slice.
func (m *manufacturer) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, m.flags)
   data = append(data, m.manufacturerName.encode()...)
   data = append(data, m.modelName.encode()...)
   return append(data, m.modelNumber.encode()...)
}

// decode decodes a byte slice into the manufacturer structure.
func (m *manufacturer) decode(data []byte) {
   m.flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   n := m.manufacturerName.decode(data)
   data = data[n:]
   n = m.modelName.decode(data)
   data = data[n:]
   m.modelNumber.decode(data)
}

type Fill byte

type GUID struct {
   Data1 uint32 // little endian
   Data2 uint16 // little endian
   Data3 uint16 // little endian
   Data4 uint64 // big endian
}

type auxKeys struct {
   Count uint16
   Keys  []auxKey
}

type auxKey struct {
   Location uint32
   Key      [16]byte
}

type ftlv struct {
   Flags  uint16
   Type   uint16
   Length uint32
   Value  []byte
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
   sourceIDEntryType                       xmrType = 34
   restrictedSourceIDEntryType             xmrType = 40
   domainIDEntryType                       xmrType = 41
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
   uplinkKIDEntryType                      xmrType = 59
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

type signature struct {
   Type   uint16
   Length uint16
   Data   []byte
}

// wmrmPublicKey is the Windows Media DRM public key used in ElGamal encryption.
const wmrmPublicKey = "C8B6AF16EE941AADAA5389B4AF2C10E356BE42AF175EF3FACE93254E7B0B3D9B982B27B5CB2341326E56AA857DBFD5C634CE2CF9EA74FCA8F2AF5957EFEEA562"

// elGamalKeyGeneration generates an ECDSA public key from the predefined WMRM public key.
func elGamalKeyGeneration() *ecdsa.PublicKey {
   data, _ := hex.DecodeString(wmrmPublicKey)
   var key ecdsa.PublicKey
   key.X = new(big.Int).SetBytes(data[:32])
   key.Y = new(big.Int).SetBytes(data[32:])
   return &key
}

// elGamalEncrypt encrypts a message m using ElGamal encryption with public key h.
func elGamalEncrypt(m, h *ecdsa.PublicKey) []byte {
   // generator
   g := elliptic.P256()
   // choose an integer y randomly
   y := big.NewInt(1) // In a real scenario, y should be truly random
   // compute c1 := g^y
   c1X, c1Y := g.ScalarBaseMult(y.Bytes())
   // Calculate shared secret s = (h^y)
   sX, sY := g.ScalarMult(h.X, h.Y, y.Bytes())
   // Second component C2 = M + s (point addition for elliptic curves)
   c2X, c2Y := g.Add(m.X, m.Y, sX, sY)
   return slices.Concat(c1X.Bytes(), c1Y.Bytes(), c2X.Bytes(), c2Y.Bytes())
}

// elGamalDecrypt decrypts a ciphertext using ElGamal decryption with private key x.
func elGamalDecrypt(ciphertext []byte, x *ecdsa.PrivateKey) []byte {
   // generator
   g := elliptic.P256()
   // Unmarshal C1 component
   c1X := new(big.Int).SetBytes(ciphertext[:32])
   c1Y := new(big.Int).SetBytes(ciphertext[32:64])
   // Unmarshal C2 component
   c2X := new(big.Int).SetBytes(ciphertext[64:96])
   c2Y := new(big.Int).SetBytes(ciphertext[96:])
   // Calculate shared secret s = C1^x
   sX, sY := g.ScalarMult(c1X, c1Y, x.D.Bytes())
   // Invert the point for subtraction
   sY.Neg(sY)
   sY.Mod(sY, g.Params().P)
   // Recover message point: M = C2 - s
   mX, mY := g.Add(c2X, c2Y, sX, sY)
   return append(mX.Bytes(), mY.Bytes()...)
}
