package playReady

import "encoding/binary"

type feature struct {
   entries  uint32
   features []uint32
}

// decode decodes a byte slice into the feature structure.
func (f *feature) decode(data []byte) int {
   f.entries = binary.BigEndian.Uint32(data)
   n := 4
   for range f.entries {
      f.features = append(f.features, binary.BigEndian.Uint32(data[n:]))
      n += 4
   }
   return n
}

// new initializes a new feature with a given type.
func (f *feature) New(Type int) {
   f.entries = 1
   f.features = []uint32{uint32(Type)}
}

// encode encodes the feature structure into a byte slice.
func (f *feature) encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, f.entries)

   for i := range f.entries {
      data = binary.BigEndian.AppendUint32(data, f.features[i])
   }

   return data
}

// keyInfo represents information about multiple keys. Renamed to avoid conflict.
type keyInfo struct {
   entries uint32
   keys    []key
}

// new initializes a new keyInfo with signing and encryption keys.
func (k *keyInfo) New(signingKey, encryptKey []byte) {
   k.entries = 2
   k.keys = make([]key, 2)
   k.keys[0].New(signingKey, 1) // Type 1 for signing key
   k.keys[1].New(encryptKey, 2) // Type 2 for encryption key
}

// encode encodes the keyInfo structure into a byte slice.
func (k *keyInfo) encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, k.entries)

   for i := range k.entries {
      data = append(data, k.keys[i].encode()...)
   }

   return data
}

// decode decodes a byte slice into the keyInfo structure.
func (k *keyInfo) decode(data []byte) {
   k.entries = binary.BigEndian.Uint32(data)
   data = data[4:]
   for range k.entries {
      var key_data key
      n := key_data.decode(data)
      k.keys = append(k.keys, key_data)
      data = data[n:]
   }
}

// key represents a cryptographic key within keyInfo. Renamed to avoid conflict.
type key struct {
   keyType   uint16
   length    uint16
   flags     uint32
   publicKey [64]byte // ECDSA P256 public key is 64 bytes (X and Y coordinates, 32 bytes each)
   usage     feature  // Features indicating key usage
}

// new initializes a new key with provided data and type.
func (k *key) New(keyData []byte, Type int) {
   k.keyType = 1  // Assuming type 1 is for ECDSA keys
   k.length = 512 // Assuming key length in bits
   copy(k.publicKey[:], keyData)
   k.usage.New(Type)
}

// encode encodes the key structure into a byte slice.
func (k *key) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, k.keyType)
   data = binary.BigEndian.AppendUint16(data, k.length)
   data = binary.BigEndian.AppendUint32(data, k.flags)
   data = append(data, k.publicKey[:]...)
   return append(data, k.usage.encode()...)
}

// decode decodes a byte slice into the key structure.
func (k *key) decode(data []byte) int {
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
