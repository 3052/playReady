package playReady

import (
   "crypto/aes"
   "crypto/ecdsa"
   "crypto/elliptic"
   "encoding/binary"
   "github.com/emmansun/gmsm/cipher"
   "math/big"
)

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

type xmlKey struct {
   PublicKey ecdsa.PublicKey
   X         [32]byte
}

type ContentKey struct {
   KeyId      [16]byte
   KeyType    uint16
   CipherType uint16
   Length     uint16
   Value      []byte
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

// they downgrade certs from the cert digest (hash of the signing key)
func (f Fill) Key() (*EcKey, error) {
   key, err := ecdsa.GenerateKey(elliptic.P256(), f)
   if err != nil {
      return nil, err
   }
   return &EcKey{key}, nil
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
