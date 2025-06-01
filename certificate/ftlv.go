package certificate

import "encoding/binary"

type ObjType uint16

const (
   BASIC ObjType = iota + 1
   DOMAIN
   PC
   DEVICE
   FEATURE
   KEY
   MANUFACTURER
   SIGNATURE
   SILVERLIGHT
   METERING
   EXTDATASIGNKEY
   EXTDATACONTAINER
   EXTDATASIGNATURE
   EXTDATA_HWIO
   SERVER
   SECURITY_VERSION
   SECURITY_VERSION_2
)

type FTLV struct {
   Flags  uint16
   Type   uint16
   Length uint32
   Value  []byte
}

func (f *FTLV) New(Flags, Type int, Value []byte) {
   f.Flags = uint16(Flags)
   f.Type = uint16(Type)
   f.Length = uint32(len(Value) + 8)
   f.Value = Value
}

func (f *FTLV) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint16(data, f.Flags)
   data = binary.BigEndian.AppendUint16(data, f.Type)
   data = binary.BigEndian.AppendUint32(data, f.Length)

   data = append(data, f.Value...)

   return data
}

func (f *FTLV) Decode(data []byte) (uint32, error) {
   var n uint32 = 0
   f.Flags = binary.BigEndian.Uint16(data[n:])
   n += 2
   f.Type = binary.BigEndian.Uint16(data[n:])
   n += 2
   f.Length = binary.BigEndian.Uint32(data[n:])
   n += 4
   f.Value = data[n:][:f.Length-8]
   n += f.Length - 8

   return n, nil
}
