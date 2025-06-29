package playReady

import (
   "41.neocities.org/playReady/xml"
   "bytes"
   "crypto/aes"
   "crypto/sha256"
   "encoding/binary"
   "encoding/hex"
   "errors"
   "github.com/emmansun/gmsm/cipher"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/curve"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/ecdsa"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/math"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/point"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/privatekey"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/publickey"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/signature"
   "math/big"
   "slices"
)

func (c *Certificate) verify(pubKey []byte) bool {
   if !bytes.Equal(c.Signature.IssuerKey, pubKey) {
      return false
   }
   publicKey := publickey.PublicKey{
      Point: point.Point{
         X:     new(big.Int).SetBytes(pubKey[:32]),
         Y:     new(big.Int).SetBytes(pubKey[32:]),
      },
      Curve: curve.Prime256v1,
   }
   message := c.Append(nil)
   message = message[:c.LengthToSignature]
   sign := c.Signature.Signature
   r := new(big.Int).SetBytes(sign[:32])
   s := new(big.Int).SetBytes(sign[32:])
   return ecdsa.Verify(
      string(message),
      signature.Signature{R: *r, S: *s},
      &publicKey,
   )
}

func elGamalDecrypt(data []byte, key *big.Int) (*big.Int, *big.Int) {
   // Unmarshal C1 component
   c1X := new(big.Int).SetBytes(data[:32])
   c1Y := new(big.Int).SetBytes(data[32:64])
   C1 := point.Point{X: c1X, Y: c1Y}
   // Unmarshal C2 component
   c2X := new(big.Int).SetBytes(data[64:96])
   c2Y := new(big.Int).SetBytes(data[96:])
   C2 := point.Point{X: c2X, Y: c2Y}
   g1 := curve.Prime256v1
   // Calculate shared secret s = C1^x
   S := math.Multiply(C1, key, g1.N, g1.A, g1.P)
   // Invert the point for subtraction
   S.Y.Neg(S.Y)
   S.Y.Mod(S.Y, g1.P)
   // Recover message point: M = C2 - s
   M := math.Add(C2, S, g1.A, g1.P)
   return M.X, M.Y
}

func elGamalEncrypt(data, key *xmlKey) []byte {
   g := curve.Prime256v1
   m := point.Point{X: data.X, Y: data.Y}
   s := point.Point{X: key.X, Y: key.Y}
   C2 := math.Add(m, s, g.A, g.P)
   return slices.Concat(
      g.G.X.Bytes(),
      g.G.Y.Bytes(),
      C2.X.Bytes(),
      C2.Y.Bytes(),
   )
}

func (x *xmlKey) New() {
   point := curve.Prime256v1.G
   x.X, x.Y = point.X, point.Y
   x.X.FillBytes(x.RawX[:])
}

type xmlKey struct {
   X *big.Int
   Y *big.Int
   RawX [32]byte
}

func Sign2(key *privatekey.PrivateKey, hash []byte) ([]byte, error) {
   // SIGN DOES SHA-256 ITSELF
   data := ecdsa.Sign(string(hash), key)
   return append(data.R.Bytes(), data.S.Bytes()...), nil
}

func (c *Chain) RequestBody(
   signEncrypt2 *privatekey.PrivateKey,
   kid []byte,
) ([]byte, error) {
   var key xmlKey
   key.New()
   cipherData, err := c.cipherData(&key)
   if err != nil {
      return nil, err
   }
   la := newLa(&key, cipherData, kid)
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
   signature, err := Sign2(signEncrypt2, signedData)
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

func aesEcbEncrypt(data, key []byte) ([]byte, error) {
   block, err := aes.NewCipher(key)
   if err != nil {
      return nil, err
   }
   data1 := make([]byte, len(data))
   cipher.NewECBEncrypter(block).CryptBlocks(data1, data)
   return data1, nil
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
