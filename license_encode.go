package playReady

import "encoding/binary"

func (l *License) Encode() []byte {
   data := l.Magic[:]
   data = binary.BigEndian.AppendUint16(data, l.Offset)
   data = binary.BigEndian.AppendUint16(data, l.Version)
   data = append(data, l.RightsID[:]...)
   value := field{
      Type: 1,
      field: []field{
         { Type: 2 }, // global policy
         { Type: 4 }, // playback policy
         {
            Type: 9, // key material
            field: []field{
               {
                  Type: 10, // content key
                  Value: nil,
               },
               {
                  Type: 42, // ecc key
                  Value: nil,
               },
               {
                  Type: 81, // aux key
                  Value: nil,
               },
            },
         },
         {
            Type: 11, // signature
            Value: nil,
         },
      },
   }
   return value.Append(data)
}

type field struct {
   Flag  uint16 // this can be 0 or 1
   Type  uint16
   Value []byte
   field []field
}

func (f *field) Append(data []byte) []byte {
   data = binary.BigEndian.AppendUint16(data, f.Flag)
   data = binary.BigEndian.AppendUint16(data, f.Type)
   data = binary.BigEndian.AppendUint32(
      data, uint32(f.size()),
   )
   if f.field != nil {
      for _, field1 := range f.field {
         data = field1.Append(data)
      }
   } else {
      data = append(data, f.Value...)
   }
   return data
}

func (f *field) decode(data []byte) (int, error) {
   f.Flag = binary.BigEndian.Uint16(data)
   n := 2
   f.Type = binary.BigEndian.Uint16(data[n:])
   n += 2
   length := binary.BigEndian.Uint32(data[n:])
   n += 4
   f.Value = data[n:length]
   n += len(f.Value)
   return n, nil
}

func (f *field) size() int {
   n := 2 // Flag
   n += 2 // Type
   n += 4 // Length
   if f.field != nil {
      for _, field1 := range f.field {
         n += field1.size()
      }
   } else {
      n += len(f.Value)
   }
   return n
}
