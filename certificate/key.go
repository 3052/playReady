package certificate

import (
   "encoding/binary"
)

type Key struct {
   Type      uint16
   Length    uint16
   Flags     uint32
   PublicKey [64]byte
   Usage     Feature
}

func (k *Key) New(Key []byte, Type int) {
   k.Type = uint16(1)
   k.Length = uint16(512)
   k.Flags = uint32(0)
   copy(k.PublicKey[:], Key)
   k.Usage.New(Type)
}

func (k *Key) Encode() []byte {
   var data []byte

   data = binary.BigEndian.AppendUint16(data, k.Type)
   data = binary.BigEndian.AppendUint16(data, k.Length)
   data = binary.BigEndian.AppendUint32(data, k.Flags)

   data = append(data, k.PublicKey[:]...)
   data = append(data, k.Usage.Encode()...)

   return data
}

func (k *Key) Decode(data []byte) (int, error) {
   k.Type = binary.BigEndian.Uint16(data)
   var n = 2

   k.Length = binary.BigEndian.Uint16(data[n:])
   n += 2

   k.Flags = binary.BigEndian.Uint32(data[n:])
   n += 4

   n += copy(k.PublicKey[:], data[n:])

   var UsageTypes Feature

   j, err := UsageTypes.Decode(data[n:])

   if err != nil {
      return 0, err
   }
   n += j

   return n, nil
}
