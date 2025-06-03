package certificate

import "encoding/binary"

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
