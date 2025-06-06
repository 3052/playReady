package playReady

import (
   "41.neocities.org/playReady/crypto"
   "bytes"
   "crypto/ecdsa"
   "crypto/sha256"
   "encoding/binary"
   "errors"
   "os"
   "slices"
)

func (c *Chain) CreateLeaf(ModelKey, SigningKey, EncryptKey crypto.EcKey) error {
   if !bytes.Equal(c.Certs[0].KeyData.Keys[0].PublicKey[:], ModelKey.PublicBytes()) {
      return errors.New("zgpriv not for cert")
   }
   if !c.Verify() {
      return errors.New("cert is not valid")
   }
   var (
      BuiltKeyInfo KeyInfo
      CertificateInfo CertInfo
      SignatureData Signature
      SignatureFtlv FTLV
      DeviceFtlv FTLV
      FeatureFtlv FTLV
      KeyInfoFtlv FTLV
      ManufacturerFtlv FTLV
      CertificateFtlv FTLV
   )
   SigningKeyDigest := sha256.Sum256(SigningKey.PublicBytes())
   CertificateInfo.New(
      c.Certs[0].CertificateInfo.SecurityLevel, SigningKeyDigest[:],
   )
   BuiltKeyInfo.New(SigningKey.PublicBytes(), EncryptKey.PublicBytes())
   CertificateFtlv.New(1, 1, CertificateInfo.Encode())
   var NewDevice Device
   NewDevice.New()
   KeyInfoFtlv.New(1, 6, BuiltKeyInfo.Encode())
   ManufacturerFtlv.New(0, 7, c.Certs[0].ManufacturerInfo.Encode())
   FeatureFtlv.New(1, 5, c.Certs[0].Features.Encode())
   DeviceFtlv.New(1, 4, NewDevice.Encode())
   NewLeafData := CertificateFtlv.Encode()
   NewLeafData = append(NewLeafData, DeviceFtlv.Encode()...)
   NewLeafData = append(NewLeafData, FeatureFtlv.Encode()...)
   NewLeafData = append(NewLeafData, KeyInfoFtlv.Encode()...)
   NewLeafData = append(NewLeafData, ManufacturerFtlv.Encode()...)
   var UnsignedCert Cert
   UnsignedCert.NewNoSig(NewLeafData)
   SignatureDigest := sha256.Sum256(UnsignedCert.Encode())
   r, s, err := ecdsa.Sign(crypto.Fill, ModelKey.Key, SignatureDigest[:])
   if err != nil {
      return err
   }
   sig := r.Bytes()
   sig = append(sig, s.Bytes()...)
   SignatureData.New(sig, ModelKey.PublicBytes())
   SignatureFtlv.New(1, 8, SignatureData.Encode())
   NewLeafData = append(NewLeafData, SignatureFtlv.Encode()...)
   UnsignedCert.Length = uint32(len(NewLeafData)) + 16
   UnsignedCert.RawData = NewLeafData
   c.Length += UnsignedCert.Length
   c.CertCount += 1
   c.Certs = slices.Insert(c.Certs, 0, UnsignedCert)
   return nil
}

func (c *Chain) Verify() bool {
   ModelBase := c.Certs[len(c.Certs)-1].SignatureData.IssuerKey
   for i := len(c.Certs) - 1; i >= 0; i-- {
      valid := c.Certs[i].Verify(ModelBase[:])

      if !valid {
         return valid
      }

      ModelBase = c.Certs[i].KeyData.Keys[0].PublicKey[:]
   }

   return true
}

func (c *Chain) Decode(data []byte) error {
   n := copy(c.Magic[:], data)

   if string(c.Magic[:]) != "CHAI" {
      return errors.New("failed to find chain magic")
   }

   data = data[n:]
   c.Version = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.Length = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.Flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.CertCount = binary.BigEndian.Uint32(data)
   data = data[4:]

   for range c.CertCount {
      var cert Cert
      i, err := cert.Decode(data)

      if err != nil {
         return err
      }

      data = data[i:]

      c.Certs = append(c.Certs, cert)
   }
   return nil
}

func (c *Chain) Encode() []byte {
   data := c.Magic[:]
   data = binary.BigEndian.AppendUint32(data, c.Version)
   data = binary.BigEndian.AppendUint32(data, c.Length)
   data = binary.BigEndian.AppendUint32(data, c.Flags)
   data = binary.BigEndian.AppendUint32(data, c.CertCount)
   for _, cert := range c.Certs {
      data = append(data, cert.Encode()...)
   }
   return data
}

func (c *Chain) LoadFile(path string) error {
   data, err := os.ReadFile(path)

   if err != nil {
      return err
   }

   return c.Decode(data)
}

type Chain struct {
   Magic     [4]byte
   Version   uint32
   Length    uint32
   Flags     uint32
   CertCount uint32
   Certs     []Cert
}
