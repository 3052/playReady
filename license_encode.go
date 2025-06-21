package playReady

import (
   "encoding/binary"
   "errors"
)

func (l *License) Encode() []byte {
   data := l.Magic[:]
   data = binary.BigEndian.AppendUint16(data, l.Offset)
   data = binary.BigEndian.AppendUint16(data, l.Version)
   data = append(data, l.RightsID[:]...)
   // outer FTLV
   // inner FTLV
   // 4.2 GlobalPolicy
   // 4.4 PlaybackPolicy
   // key FTLV
   // 4.9.10 ContentKey
   // 4.9.42 eccKey
   // 4.9.81 auxKeys
   return data
}

func (f *ftlv) New(Type uint16, value []byte) {
   f.Flags = 1
   f.Type = Type
   f.Length = uint32(len(value)) + 8
   f.Value = value
}

type ftlv struct {
   Flags  uint16
   Type   uint16
   Length uint32
   Value  []byte // The raw value bytes of the FTLV object
}

func (f *ftlv) verify(data []byte) bool {
   if f.Length >= 8 {
      if int(f.Length) <= len(data) {
         return true
      }
   }
   return false
}

func (f *ftlv) decode(data []byte) (int, error) {
   f.Flags = binary.BigEndian.Uint16(data)
   n := 2
   f.Type = binary.BigEndian.Uint16(data[n:])
   n += 2
   f.Length = binary.BigEndian.Uint32(data[n:])
   if !f.verify(data) {
      return 0, errors.New("FTLV length invalid")
   }
   n += 4
   f.Value = data[n:f.Length]
   n += len(f.Value)
   return n, nil
}

func (f *ftlv) size() int {
   n := 2 // Flags
   n += 2 // Type
   n += 4 // Length
   n += len(f.Value)
   return n
}

func (f *ftlv) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, f.Flags)
   data = binary.BigEndian.AppendUint16(data, f.Type)
   data = binary.BigEndian.AppendUint32(data, f.Length)
   return append(data, f.Value...)
}
