package license

import (
   "encoding/base64"
   "encoding/binary"
   "encoding/hex"
   "strings"
)

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
   data = binary.BigEndian.AppendUint64(data, k.Data4)

   return data
}

func (k *Guid) Bytes() []byte {
   var data []byte
   data = binary.LittleEndian.AppendUint32(data, k.Data1)
   data = binary.LittleEndian.AppendUint16(data, k.Data2)
   data = binary.LittleEndian.AppendUint16(data, k.Data3)
   data = binary.BigEndian.AppendUint64(data, k.Data4)

   return data
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

   b.WriteString(
      data[:4],
   )
   b.WriteByte('-')

   b.WriteString(
      data[4:],
   )
   return b.String()
}
