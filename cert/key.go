package cert

import "encoding/binary"

func (m *Manufacturer) Decode(data []byte) error {
   m.Flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   n, err := m.ManufacturerName.Decode(data)
   if err != nil {
      return err
   }
   data = data[n:]
   n, err = m.ModelName.Decode(data)
   if err != nil {
      return err
   }
   data = data[n:]
   _, err = m.ModelNumber.Decode(data)
   if err != nil {
      return err
   }
   return nil
}

type Key struct {
   Type      uint16
   Length    uint16
   Flags     uint32
   PublicKey [64]byte
   Usage     Feature
}

func (k *Key) New(Key []byte, Type int) {
   k.Type = uint16(1)
   k.Length = uint16(512)
   k.Flags = uint32(0)
   copy(k.PublicKey[:], Key)
   k.Usage.New(Type)
}

func (k *Key) Encode() []byte {
   var data []byte

   data = binary.BigEndian.AppendUint16(data, k.Type)
   data = binary.BigEndian.AppendUint16(data, k.Length)
   data = binary.BigEndian.AppendUint32(data, k.Flags)

   data = append(data, k.PublicKey[:]...)
   data = append(data, k.Usage.Encode()...)

   return data
}

func (k *Key) Decode(data []byte) (int, error) {
   k.Type = binary.BigEndian.Uint16(data)
   var n = 2

   k.Length = binary.BigEndian.Uint16(data[n:])
   n += 2

   k.Flags = binary.BigEndian.Uint32(data[n:])
   n += 4

   n += copy(k.PublicKey[:], data[n:])

   var UsageTypes Feature

   j, err := UsageTypes.Decode(data[n:])

   if err != nil {
      return 0, err
   }
   n += j

   return n, nil
}
func (c *CertInfo) New(SecurityLevel uint32, Digest []byte) {
   c.SecurityLevel = SecurityLevel
   c.Flags = 0
   c.Type = 2
   copy(c.Digest[:], Digest)
   c.Expiry = 4294967295
}

type CertInfo struct {
   CertificateId [16]byte
   SecurityLevel uint32
   Flags         uint32
   Type          uint32
   Digest        [32]byte
   Expiry        uint32
   ClientId      [16]byte
}

func (c *CertInfo) Encode() []byte {
   var data []byte
   data = append(data, c.CertificateId[:]...)

   data = binary.BigEndian.AppendUint32(data, c.SecurityLevel)
   data = binary.BigEndian.AppendUint32(data, c.Flags)
   data = binary.BigEndian.AppendUint32(data, c.Type)

   data = append(data, c.Digest[:]...)

   data = binary.BigEndian.AppendUint32(data, c.Expiry)

   data = append(data, c.ClientId[:]...)

   return data
}

func (c *CertInfo) Decode(data []byte) error {
   n := copy(c.CertificateId[:], data)
   data = data[n:]

   c.SecurityLevel = binary.BigEndian.Uint32(data)
   data = data[4:]

   c.Flags = binary.BigEndian.Uint32(data)
   data = data[4:]

   c.Type = binary.BigEndian.Uint32(data)
   data = data[4:]

   n = copy(c.Digest[:], data)
   data = data[n:]

   c.Expiry = binary.BigEndian.Uint32(data)
   data = data[4:]

   copy(c.ClientId[:], data)

   return nil
}

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
