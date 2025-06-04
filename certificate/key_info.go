package certificate

import "encoding/binary"

type Feature struct {
   Entries  uint32
   Features []uint32
}

func (f *Feature) New(Type int) {
   f.Entries = 1

   f.Features = append(f.Features, uint32(Type))
}

func (f *Feature) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, f.Entries)

   for i := range f.Entries {
      data = binary.BigEndian.AppendUint32(data, f.Features[i])
   }

   return data
}

func (f *Feature) Decode(data []byte) (int, error) {
   f.Entries = binary.BigEndian.Uint32(data)

   var n = 4

   for range f.Entries {
      f.Features = append(f.Features, binary.BigEndian.Uint32(data[n:]))
      n += 4
   }

   return n, nil
}

type KeyInfo struct {
   Entries uint32
   Keys    []Key
}

func (k *KeyInfo) New(SigningKey, EncryptKey []byte) {
   k.Entries = uint32(2)

   k.Keys = make([]Key, 2)

   k.Keys[0].New(SigningKey, 1)
   k.Keys[1].New(EncryptKey, 2)
}

func (k *KeyInfo) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, k.Entries)

   for i := range k.Entries {
      data = append(data, k.Keys[i].Encode()...)
   }

   return data
}

func (k *KeyInfo) Decode(data []byte) error {
   k.Entries = binary.BigEndian.Uint32(data)
   data = data[4:]

   for range k.Entries {
      var KeyData Key

      i, err := KeyData.Decode(data)

      if err != nil {
         return err
      }

      k.Keys = append(k.Keys, KeyData)

      data = data[i:]
   }

   return nil
}
