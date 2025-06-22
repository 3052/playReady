package playReady

import "encoding/binary"

func (f *field) New(Type uint16, Value []byte) {
   f.Flag = 1
   f.Type = Type
   f.Value = Value
}

// google.golang.org/protobuf/encoding/protowire#ConsumeField
type field struct {
   Flag  uint16 // this can be 0 or 1
   Type  uint16
   Value []byte
   field []field
}

func (l *License) Encode() []byte {
   data := l.Magic[:]
   data = binary.BigEndian.AppendUint16(data, l.Offset)
   data = binary.BigEndian.AppendUint16(data, l.Version)
   data = append(data, l.RightsID[:]...)
   // field{
   //    Type: 1,
   //    Value: []field{
   //       { Type: 2 }, // global policy
   //       { Type: 4 }, // global policy
   //       {
   //          Type: 9,
   //          Value: []field{
   //             { Type: 10 }, // content key
   //             { Type: 42 }, // ecc key
   //             { Type: 81 }, // aux key
   //          },
   //       },
   //       { Type: 11 }, // signature
   //    },
   // }
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

func (f *field) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, f.Flag)
   data = binary.BigEndian.AppendUint16(data, f.Type)
   data = binary.BigEndian.AppendUint32(
      data, uint32(f.size()),
   )
   if f.field != nil {
      for _, field1 := range f.field {
         data = append(data, field1.encode()...)
      }
   } else {
      data = append(data, f.Value...)
   }
   return data
}
