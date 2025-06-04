package license

import "encoding/binary"

type ECCKey struct {
   Curve  uint16
   Length uint16
   Value  []byte
}

func (e *ECCKey) Decode(data []byte) error {
   e.Curve = binary.BigEndian.Uint16(data)
   data = data[2:]

   e.Length = binary.BigEndian.Uint16(data)
   data = data[2:]

   e.Value = make([]byte, e.Length)
   copy(e.Value, data)

   return nil
}

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
