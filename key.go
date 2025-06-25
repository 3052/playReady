package playReady

import (
   "41.neocities.org/playReady/xml"
   "crypto/aes"
   "crypto/ecdsa"
   "crypto/elliptic"
   "encoding/binary"
   "encoding/hex"
   "errors"
   "github.com/emmansun/gmsm/cipher"
   "math/big"
   "slices"
)

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

func (x *xmlKey) New() {
   x.PublicKey.X, x.PublicKey.Y = elliptic.P256().ScalarBaseMult([]byte{1})
   x.PublicKey.X.FillBytes(x.X[:])
}

func (x *xmlKey) aesIv() []byte {
   return x.X[:16]
}

func (x *xmlKey) aesKey() []byte {
   return x.X[16:]
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

const wmrmPublicKey = "C8B6AF16EE941AADAA5389B4AF2C10E356BE42AF175EF3FACE93254E7B0B3D9B982B27B5CB2341326E56AA857DBFD5C634CE2CF9EA74FCA8F2AF5957EFEEA562"

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

func elGamalEncrypt(data, key *ecdsa.PublicKey) []byte {
   g := elliptic.P256()
   y := big.NewInt(1) // In a real scenario, y should be truly random
   c1x, c1y := g.ScalarBaseMult(y.Bytes())
   sX, sY := g.ScalarMult(key.X, key.Y, y.Bytes())
   c2X, c2Y := g.Add(data.X, data.Y, sX, sY)
   return slices.Concat(c1x.Bytes(), c1y.Bytes(), c2X.Bytes(), c2Y.Bytes())
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

func newLa(m *ecdsa.PublicKey, cipherData, kid []byte) *xml.La {
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

func elGamalKeyGeneration() *ecdsa.PublicKey {
   data, _ := hex.DecodeString(wmrmPublicKey)
   var key ecdsa.PublicKey
   key.X = new(big.Int).SetBytes(data[:32])
   key.Y = new(big.Int).SetBytes(data[32:])
   return &key
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

func (c *ContentKey) decrypt(key *ecdsa.PrivateKey, aux *AuxKeys) error {
   switch c.CipherType {
   case 3:
      decrypted := elGamalDecrypt(c.Value, key)
      n := copy(c.Integrity[:], decrypted)
      decrypted = decrypted[n:]
      copy(c.Key[:], decrypted)
      return nil
   case 6:
      return c.scalable(key, aux)
   }
   return errors.New("cannot decrypt key")
}

func (c *ContentKey) scalable(key *ecdsa.PrivateKey, aux *AuxKeys) error {
   rootKeyInfo, leafKeys := c.Value[:144], c.Value[144:]
   rootKey := rootKeyInfo[128:]
   decrypted := elGamalDecrypt(rootKeyInfo[:128], key)
   var (
      ci [16]byte
      ck [16]byte
   )
   for i := range 16 {
      ci[i] = decrypted[i*2]
      ck[i] = decrypted[i*2+1]
   }
   magicConstantZero, err := c.magicConstantZero()
   if err != nil {
      return err
   }
   rgbUplinkXkey := xorKey(ck[:], magicConstantZero)
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
   rgbKey, err := aesEcbEncrypt(leafKeys, auxKeyCalc)
   if err != nil {
      return err
   }
   rgbKey, err = aesEcbEncrypt(rgbKey, oSecondaryKey)
   if err != nil {
      return err
   }
   n := copy(c.Integrity[:], rgbKey)
   rgbKey = rgbKey[n:]
   copy(c.Key[:], rgbKey)
   return nil
}

// magicConstantZero returns a specific hex-decoded byte slice.
func (*ContentKey) magicConstantZero() ([]byte, error) {
   return hex.DecodeString("7ee9ed4af773224f00b8ea7efb027cbb")
}

type EcKey [1]*ecdsa.PrivateKey

func (e *EcKey) Decode(data []byte) {
   var public ecdsa.PublicKey
   public.Curve = elliptic.P256()
   public.X, public.Y = public.Curve.ScalarBaseMult(data)
   var private ecdsa.PrivateKey
   private.D = new(big.Int).SetBytes(data)
   private.PublicKey = public
   e[0] = &private
}

// Private returns the private key bytes.
func (e EcKey) Private() []byte {
   return e[0].D.Bytes()
}

// PublicBytes returns the public key bytes.
func (e *EcKey) public() []byte {
   return append(e[0].PublicKey.X.Bytes(), e[0].PublicKey.Y.Bytes()...)
}

// they downgrade certs from the cert digest (hash of the signing key)
func (f Fill) Key() (*EcKey, error) {
   key, err := ecdsa.GenerateKey(elliptic.P256(), f)
   if err != nil {
      return nil, err
   }
   return &EcKey{key}, nil
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

type KeyData struct {
   KeyType   uint16
   Length    uint16
   Flags     uint32
   PublicKey [64]byte // ECDSA P256 public key (X and Y coordinates)
   Usage     CertFeatures
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

type xmlKey struct {
   PublicKey ecdsa.PublicKey
   X         [32]byte
}

///

type ContentKey struct {
   KeyId      [16]byte
   KeyType    uint16
   CipherType uint16
   Length     uint16
   Value      []byte
   
   Integrity  [16]byte
   Key        [16]byte
}
