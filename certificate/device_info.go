package certificate

import "encoding/binary"

type ManufacturerInfo struct {
   Length uint32
   Value  string
}

func (m *ManufacturerInfo) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, m.Length)
   data = append(data, []byte(m.Value)...)

   return data
}

func (m *ManufacturerInfo) Decode(data []byte) (uint32, error) {
   m.Length = binary.BigEndian.Uint32(data)
   var n uint32 = 4

   paddedLength := (m.Length + 3) &^ 3

   m.Value = string(data[n:][:paddedLength])

   n += paddedLength

   return n, nil
}

type Device struct {
   MaxLicenseSize       uint32
   MaxHeaderSize        uint32
   MaxLicenseChainDepth uint32
}

func (d *Device) New() {
   d.MaxLicenseSize = uint32(10240)
   d.MaxHeaderSize = uint32(15360)
   d.MaxLicenseChainDepth = uint32(2)
}

func (d *Device) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, d.MaxLicenseSize)
   data = binary.BigEndian.AppendUint32(data, d.MaxHeaderSize)
   data = binary.BigEndian.AppendUint32(data, d.MaxLicenseChainDepth)

   return data
}
