package playReady

import (
   "41.neocities.org/playReady/certificate"
   "bytes"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/sha256"
   "encoding/binary"
   "errors"
   "math/big"
)

type Cert struct {
   Magic             [4]byte
   Version           uint32
   Length            uint32
   LengthToSignature uint32
   RawData           []byte
   CertificateInfo   *CertInfo
   Features          *certificate.Feature
   KeyData           *certificate.KeyInfo
   ManufacturerInfo  *Manufacturer
   SignatureData     *certificate.Signature
}

func (c *Cert) Verify(PubKey []byte) bool {
   if !bytes.Equal(c.SignatureData.IssuerKey, PubKey) {
      return false
   }
   data := c.Encode()
   data = data[:c.LengthToSignature]
   x := new(big.Int).SetBytes(PubKey[:32])
   y := new(big.Int).SetBytes(PubKey[32:])
   PublicKey := &ecdsa.PublicKey{
      Curve: elliptic.P256(),
      X:     x,
      Y:     y,
   }
   Sig := c.SignatureData.SignatureData
   SignatureDigest := sha256.Sum256(data)
   r, s := new(big.Int).SetBytes(Sig[:32]), new(big.Int).SetBytes(Sig[32:])
   return ecdsa.Verify(PublicKey, SignatureDigest[:], r, s)
}

func (c *Cert) Decode(data []byte) (int, error) {
   n := copy(c.Magic[:], data)

   if string(c.Magic[:]) != "CERT" {
      return 0, errors.New("failed to find cert magic")
   }

   c.Version = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.Length = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.LengthToSignature = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.RawData = data[n:][:c.Length-16]
   n += len(c.RawData)

   var sum uint32
   for sum < c.Length-16 {
      var ftlv FTLV

      j, err := ftlv.Decode(c.RawData[sum:])

      if err != nil {
         return 0, err
      }

      var ObjectType = ObjType(ftlv.Type)

      switch ObjectType {
      case BASIC:
         c.CertificateInfo = new(CertInfo)

         err := c.CertificateInfo.Decode(ftlv.Value)

         if err != nil {
            return 0, err
         }

      case FEATURE:
         c.Features = new(certificate.Feature)

         _, err := c.Features.Decode(ftlv.Value)
         if err != nil {
            return 0, err
         }

      case KEY:
         c.KeyData = new(certificate.KeyInfo)
         err := c.KeyData.Decode(ftlv.Value)
         if err != nil {
            return 0, err
         }

      case MANUFACTURER:
         c.ManufacturerInfo = new(Manufacturer)

         err := c.ManufacturerInfo.Decode(ftlv.Value)

         if err != nil {
            return 0, err
         }

      case SIGNATURE:
         c.SignatureData = new(certificate.Signature)
         err := c.SignatureData.Decode(ftlv.Value)

         if err != nil {
            return 0, err
         }

      }

      sum += j
   }

   return n, nil
}

func (c *Cert) Encode() []byte {
   var data []byte
   data = append(data, c.Magic[:]...)

   data = binary.BigEndian.AppendUint32(data, c.Version)
   data = binary.BigEndian.AppendUint32(data, c.Length)
   data = binary.BigEndian.AppendUint32(data, c.LengthToSignature)

   return append(data, c.RawData[:]...)
}

func (c *Cert) NewNoSig(Value []byte) {
   copy(c.Magic[:], "CERT")
   c.Version = 1
   c.Length = uint32(len(Value)) + 16 + 144
   c.LengthToSignature = uint32(len(Value)) + 16
   c.RawData = make([]byte, len(Value))
   copy(c.RawData, Value)
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

func (c *CertInfo) New(SecurityLevel uint32, Digest []byte) {
   c.SecurityLevel = SecurityLevel
   c.Flags = 0
   c.Type = 2
   copy(c.Digest[:], Digest)
   c.Expiry = 4294967295
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

func (c *CertInfo) Encode() []byte {
   data := c.CertificateId[:]
   data = binary.BigEndian.AppendUint32(data, c.SecurityLevel)
   data = binary.BigEndian.AppendUint32(data, c.Flags)
   data = binary.BigEndian.AppendUint32(data, c.Type)
   data = append(data, c.Digest[:]...)
   data = binary.BigEndian.AppendUint32(data, c.Expiry)
   return append(data, c.ClientId[:]...)
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
