package playReady

import (
   "bytes"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/sha256"
   "encoding/binary"
   "errors"
   "math/big"
)

func (c *Cert) Verify(PubKey []byte) bool {
   if bytes.Compare(c.SignatureData.IssuerKey, PubKey) != 0 {
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

   if !ecdsa.Verify(PublicKey, SignatureDigest[:], r, s) {
      return false
   }

   return true
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

   var sum uint32 = 0
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
         c.Features = new(Feature)

         _, err := c.Features.Decode(ftlv.Value)
         if err != nil {
            return 0, err
         }

      case KEY:
         c.KeyData = new(KeyInfo)
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
         c.SignatureData = new(Signature)
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
type Cert struct {
   Magic             [4]byte
   Version           uint32
   Length            uint32
   LengthToSignature uint32
   RawData           []byte
   CertificateInfo   *CertInfo
   Features          *Feature
   KeyData           *KeyInfo
   ManufacturerInfo  *Manufacturer
   SignatureData     *Signature
}

func (c *Cert) NewNoSig(Value []byte) {
   copy(c.Magic[:], "CERT")
   c.Version = 1
   c.Length = uint32(len(Value)) + 16 + 144
   c.LengthToSignature = uint32(len(Value)) + 16
   c.RawData = make([]byte, len(Value))
   copy(c.RawData, Value)
}

