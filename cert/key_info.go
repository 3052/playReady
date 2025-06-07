package cert

import "encoding/binary"

type Signature struct {
   Type            uint16
   SignatureLength uint16
   SignatureData   []byte
   IssuerLength    uint32
   IssuerKey       []byte
}

func (s *Signature) New(Signature, SigningKey []byte) {
   s.Type = 1
   s.SignatureLength = uint16(len(Signature))
   s.SignatureData = make([]byte, len(Signature))
   copy(s.SignatureData, Signature)
   s.IssuerLength = uint32(len(SigningKey))
   s.IssuerKey = make([]byte, len(SigningKey))
   copy(s.IssuerKey, SigningKey)
}

func (s *Signature) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint16(data, s.Type)
   data = binary.BigEndian.AppendUint16(data, s.SignatureLength)
   data = append(data, s.SignatureData...)
   data = binary.BigEndian.AppendUint32(data, s.IssuerLength*8)
   data = append(data, s.IssuerKey...)

   return data
}

func (s *Signature) Decode(data []byte) error {
   s.Type = binary.BigEndian.Uint16(data)
   data = data[2:]

   s.SignatureLength = binary.BigEndian.Uint16(data)
   data = data[2:]

   s.SignatureData = make([]byte, int(s.SignatureLength))
   n := copy(s.SignatureData[:], data)
   data = data[n:]

   s.IssuerLength = binary.BigEndian.Uint32(data)
   data = data[4:]

   s.IssuerKey = make([]byte, int(s.IssuerLength)/8)
   copy(s.IssuerKey[:], data)

   return nil
}

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
