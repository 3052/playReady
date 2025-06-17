package playReady

import (
   "crypto/ecdsa"
   "crypto/elliptic"
   "encoding/binary"
   "encoding/hex"
   "math/big"
)

// they downgrade certs from the cert digest (hash of the signing key)
func (f Fill) key() (*EcKey, error) {
   key, err := ecdsa.GenerateKey(elliptic.P256(), f)
   if err != nil {
      return nil, err
   }
   return &EcKey{key}, nil
}

func (e *EcKey) decode(data []byte) {
   var public ecdsa.PublicKey
   public.Curve = elliptic.P256()
   public.X, public.Y = public.Curve.ScalarBaseMult(data)
   var private ecdsa.PrivateKey
   private.D = new(big.Int).SetBytes(data)
   private.PublicKey = public
   e[0] = &private
}

type xmlKey struct {
   PublicKey ecdsa.PublicKey
   X         [32]byte
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

type ContentKey struct {
   KeyID      GUID
   KeyType    uint16
   CipherType uint16
   Length     uint16
   Value      []byte
   Integrity  GUID
   Key        [16]byte
}

type EcKey [1]*ecdsa.PrivateKey

// Private returns the private key bytes.
func (e EcKey) Private() []byte {
   return e[0].D.Bytes()
}

// PublicBytes returns the public key bytes.
func (e *EcKey) Public() []byte {
   return append(e[0].PublicKey.X.Bytes(), e[0].PublicKey.Y.Bytes()...)
}

type eccKey struct {
   Curve  uint16
   Length uint16
   Value  []byte
}

type features struct {
   entries  uint32
   features []uint32
}

func (f *features) New(Type int) {
   f.entries = 1
   f.features = []uint32{uint32(Type)}
}

type keyInfo struct {
   entries uint32
   keys    []keyData
}

// decode decodes a byte slice into the keyInfo structure.
func (k *keyInfo) decode(data []byte) {
   k.entries = binary.BigEndian.Uint32(data)
   data = data[4:]
   k.keys = make([]keyData, k.entries)
   for i := range k.entries {
      var key keyData
      n := key.decode(data)
      k.keys[i] = key
      data = data[n:]
   }
}

// decode decodes a byte slice into the key structure.
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

func (f *features) decode(data []byte) int {
   f.entries = binary.BigEndian.Uint32(data)
   n := 4
   for range f.entries {
      f.features = append(f.features, binary.BigEndian.Uint32(data[n:]))
      n += 4
   }
   return n
}

type keyData struct {
   keyType   uint16
   length    uint16
   flags     uint32
   // ECDSA P256 public key is 64 bytes (X and Y coordinates, 32 bytes each)
   publicKey [64]byte
   // Features indicating key usage
   usage     features
}

// new initializes a new key with provided data and type.
func (k *keyData) New(data []byte, Type int) {
   k.keyType = 1  // Assuming type 1 is for ECDSA keys
   k.length = 512 // Assuming key length in bits
   copy(k.publicKey[:], data)
   k.usage.New(Type)
}

// encode encodes the key structure into a byte slice.
func (k *keyData) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, k.keyType)
   data = binary.BigEndian.AppendUint16(data, k.length)
   data = binary.BigEndian.AppendUint32(data, k.flags)
   data = append(data, k.publicKey[:]...)
   return append(data, k.usage.encode()...)
}

// new initializes a new keyInfo with signing and encryption keys.
func (k *keyInfo) New(signingKey, encryptKey []byte) {
   k.entries = 2
   k.keys = make([]keyData, 2)
   k.keys[0].New(signingKey, 1) // Type 1 for signing key
   k.keys[1].New(encryptKey, 2) // Type 2 for encryption key
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

// magicConstantZero returns a specific hex-decoded byte slice.
func (*ContentKey) magicConstantZero() ([]byte, error) {
   return hex.DecodeString("7ee9ed4af773224f00b8ea7efb027cbb")
}

func (f *features) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, f.entries)

   for i := range f.entries {
      data = binary.BigEndian.AppendUint32(data, f.features[i])
   }

   return data
}

// encode encodes the keyInfo structure into a byte slice.
func (k *keyInfo) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, k.entries)

   for i := range k.entries {
      data = append(data, k.keys[i].encode()...)
   }

   return data
}

// Decode decodes a byte slice into an ECCKey structure.
func (e *eccKey) decode(data []byte) {
   e.Curve = binary.BigEndian.Uint16(data)
   data = data[2:]
   e.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   e.Value = data
}

// decode decodes a byte slice into a ContentKey structure.
func (c *ContentKey) decode(data []byte) {
   c.KeyID.Decode(data[:])
   data = data[16:]
   c.KeyType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.CipherType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.Value = data
}
