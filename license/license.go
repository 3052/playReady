package license

import "encoding/binary"

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
