package license

import (
   "41.neocities.org/playReady/crypto"
   "encoding/base64"
   "encoding/binary"
   "encoding/hex"
   "errors"
   "strings"
)

func (c *ContentKey) Scalable(key crypto.EcKey, aux_keys *AuxKeys) error {
   rootKeyInfo := c.Value[:144]
   rootKey := rootKeyInfo[128:]
   leafKeys := c.Value[144:]
   var el_gamal crypto.ElGamal
   decrypted := el_gamal.Decrypt(rootKeyInfo[:128], key.Key.D)
   var CI [16]byte
   var CK [16]byte
   for i := range 16 {
      CI[i] = decrypted[i*2]
      CK[i] = decrypted[i*2+1]
   }
   magicConstantZero, err := hex.DecodeString("7ee9ed4af773224f00b8ea7efb027cbb")
   if err != nil {
      return err
   }
   rgbUplinkXKey := XorKey(CK[:], magicConstantZero)
   var aes crypto.Aes
   contentKeyPrime := aes.EncryptECB(CK[:], rgbUplinkXKey)
   auxKeyCalc := aes.EncryptECB(contentKeyPrime, aux_keys.Keys[0].Key[:])
   UpLinkXKey := XorKey(auxKeyCalc, new([16]byte)[:])
   oSecondaryKey := aes.EncryptECB(CK[:], rootKey)
   rgbKey := aes.EncryptECB(UpLinkXKey, leafKeys)
   rgbKey = aes.EncryptECB(oSecondaryKey, rgbKey)
   c.Integrity.Decode(rgbKey[:])
   rgbKey = rgbKey[16:]
   c.Key.Decode(rgbKey[:])
   return nil
}

func (c *ContentKey) Decrypt(key crypto.EcKey, aux_keys *AuxKeys) error {
   switch c.CipherType {
   case 3:
      decrypted := c.ECC256(key)
      c.Integrity.Decode(decrypted)
      decrypted = decrypted[16:]
      c.Key.Decode(decrypted)
      return nil
   case 6:
      return c.Scalable(key, aux_keys)
   }
   return errors.New("cant decrypt key")
}

type Guid struct {
   Data1 uint32 // little endian
   Data2 uint16 // little endian
   Data3 uint16 // little endian
   Data4 uint64 // big endian
}

func (k *Guid) Decode(data []byte) {
   k.Data1 = binary.LittleEndian.Uint32(data)
   data = data[4:]
   k.Data2 = binary.LittleEndian.Uint16(data)
   data = data[2:]
   k.Data3 = binary.LittleEndian.Uint16(data)
   data = data[2:]
   k.Data4 = binary.BigEndian.Uint64(data)
}

func (k *Guid) Base64Decode(data string) error {
   decoded, err := base64.StdEncoding.DecodeString(data)
   if err != nil {
      return err
   }
   k.Decode(decoded)
   return nil
}

func (k *Guid) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, k.Data1)
   data = binary.BigEndian.AppendUint16(data, k.Data2)
   data = binary.BigEndian.AppendUint16(data, k.Data3)
   return binary.BigEndian.AppendUint64(data, k.Data4)
}

func (k *Guid) Bytes() []byte {
   var data []byte
   data = binary.LittleEndian.AppendUint32(data, k.Data1)
   data = binary.LittleEndian.AppendUint16(data, k.Data2)
   data = binary.LittleEndian.AppendUint16(data, k.Data3)
   return binary.BigEndian.AppendUint64(data, k.Data4)
}

func (k *Guid) Hex() string {
   data := k.Encode()
   dst := make([]byte, hex.EncodedLen(len(data)))
   hex.Encode(dst, data)
   return string(dst)
}

func (k *Guid) Uuid() string {
   var b strings.Builder
   b.WriteString(
      hex.EncodeToString(binary.LittleEndian.AppendUint32(nil, k.Data1)),
   )
   b.WriteByte('-')
   b.WriteString(
      hex.EncodeToString(binary.LittleEndian.AppendUint16(nil, k.Data2)),
   )
   b.WriteByte('-')
   b.WriteString(
      hex.EncodeToString(binary.LittleEndian.AppendUint16(nil, k.Data3)),
   )
   b.WriteByte('-')
   data := hex.EncodeToString(binary.BigEndian.AppendUint64(nil, k.Data4))
   b.WriteString(data[:4])
   b.WriteByte('-')
   b.WriteString(data[4:])
   return b.String()
}

func (c *ContentKey) ECC256(key crypto.EcKey) []byte {
   var el_gamal crypto.ElGamal
   return el_gamal.Decrypt(c.Value, key.Key.D)
}

type ContentKey struct {
   KeyId      Guid
   KeyType    uint16
   CipherType uint16
   Length     uint16
   Value      []byte
   Integrity  Guid
   Key        Guid
}

func (c *ContentKey) Decode(data []byte) error {
   c.KeyId.Decode(data[:])
   data = data[16:]
   c.KeyType = binary.BigEndian.Uint16(data)
   data = data[2:]

   c.CipherType = binary.BigEndian.Uint16(data)
   data = data[2:]

   c.Length = binary.BigEndian.Uint16(data)
   data = data[2:]

   c.Value = make([]byte, c.Length)

   copy(c.Value[:], data)

   return nil
}

func XorKey(root, second []byte) []byte {
   data := make([]byte, len(second))
   copy(data, root)
   for i := range 16 {
      data[i] ^= second[i]
   }
   return data
}

type FTLV struct {
   Flags  uint16
   Type   uint16
   Length uint32
   Value  []byte
}

func (f *FTLV) Decode(data []byte) (uint32, error) {
   var n uint32
   f.Flags = binary.BigEndian.Uint16(data[n:])
   n += 2
   f.Type = binary.BigEndian.Uint16(data[n:])
   n += 2
   f.Length = binary.BigEndian.Uint32(data[n:])
   n += 4
   f.Value = data[n:][:f.Length-8]
   n += f.Length - 8

   return n, nil
}

func (f *FTLV) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint16(data, f.Flags)
   data = binary.BigEndian.AppendUint16(data, f.Type)
   data = binary.BigEndian.AppendUint32(data, f.Length)
   return append(data, f.Value...)
}

type AuxKeys struct {
   Count uint16
   Keys  []AuxKey
}

func (a *AuxKeys) Decode(data []byte) error {
   a.Count = binary.BigEndian.Uint16(data)
   data = data[2:]

   for range a.Count {
      var Key AuxKey

      i, err := Key.Decode(data)

      if err != nil {
         return err
      }

      a.Keys = append(a.Keys, Key)

      data = data[i:]
   }

   return nil
}

type AuxKey struct {
   Location uint32
   Key      [16]byte
}

func (a *AuxKey) Decode(data []byte) (int, error) {
   a.Location = binary.BigEndian.Uint32(data)
   data = data[4:]

   n := copy(a.Key[:], data)

   return n + 4, nil
}

type ECCKey struct {
   Curve  uint16
   Length uint16
   Value  []byte
}

func (e *ECCKey) Decode(data []byte) error {
   e.Curve = binary.BigEndian.Uint16(data)
   data = data[2:]

   e.Length = binary.BigEndian.Uint16(data)
   data = data[2:]

   e.Value = make([]byte, e.Length)
   copy(e.Value, data)

   return nil
}

type Signature struct {
   Type   uint16
   Length uint16
   Data   []byte
}

func (s *Signature) Decode(data []byte) error {
   s.Type = binary.BigEndian.Uint16(data)
   data = data[2:]
   s.Length = binary.BigEndian.Uint16(data)
   data = data[2:]

   s.Data = make([]byte, s.Length)
   copy(s.Data, data)

   return nil
}
