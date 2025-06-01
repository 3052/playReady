package certificate

import "encoding/binary"

type Manufacturer struct {
   Flags            uint32
   ManufacturerName ManufacturerInfo
   ModelName        ManufacturerInfo
   ModelNumber      ManufacturerInfo
}

func (m *Manufacturer) Encode() []byte {
   var data []byte

   data = binary.BigEndian.AppendUint32(data, m.Flags)
   data = append(data, m.ManufacturerName.Encode()...)
   data = append(data, m.ModelName.Encode()...)
   data = append(data, m.ModelNumber.Encode()...)

   return data
}

func (m *Manufacturer) Decode(data []byte) error {
   m.Flags = binary.BigEndian.Uint32(data)
   data = data[4:]

   j, err := m.ManufacturerName.Decode(data)
   if err != nil {
      return err
   }
   data = data[j:]

   j, err = m.ModelName.Decode(data)
   if err != nil {
      return err
   }
   data = data[j:]

   j, err = m.ModelNumber.Decode(data)
   if err != nil {
      return err
   }

   return nil
}
