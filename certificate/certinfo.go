package certificate

import (
   "crypto/rand"
   "encoding/binary"
)

type CertInfo struct {
   CertificateId [16]byte
   SecurityLevel uint32
   Flags         uint32
   Type          uint32
   Digest        [32]byte
   Expiry        uint32
   ClientId      [16]byte
}

func (c *CertInfo) New(SecurityLevel uint32, Digest []byte) error {
   _, err := rand.Read(c.CertificateId[:])
   if err != nil {
      return err
   }

   c.SecurityLevel = SecurityLevel
   c.Flags = 0
   c.Type = 2
   copy(c.Digest[:], Digest)

   c.Expiry = 4294967295

   _, err = rand.Read(c.ClientId[:])
   if err != nil {
      return err
   }

   return nil
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
