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
