package c

import (
   "41.neocities.org/playReady/a"
   "41.neocities.org/playReady/b"
   "bytes"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/sha256"
   "encoding/binary"
   "errors"
   "math/big"
   "slices"
)

type Device struct {
   MaxLicenseSize       uint32
   MaxHeaderSize        uint32
   MaxLicenseChainDepth uint32
}

func (d *Device) New() {
   d.MaxLicenseSize = 10240
   d.MaxHeaderSize = 15360
   d.MaxLicenseChainDepth = 2
}

func (d *Device) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, d.MaxLicenseSize)
   data = binary.BigEndian.AppendUint32(data, d.MaxHeaderSize)
   return binary.BigEndian.AppendUint32(data, d.MaxLicenseChainDepth)
}

func (c *Chain) CreateLeaf(ModelKey, SigningKey, EncryptKey a.EcKey) error {
   if !bytes.Equal(c.Certs[0].KeyData.Keys[0].PublicKey[:], ModelKey.PublicBytes()) {
      return errors.New("zgpriv not for cert")
   }
   if !c.Verify() {
      return errors.New("cert is not valid")
   }
   var (
      BuiltKeyInfo     KeyInfo
      CertificateInfo  CertInfo
      SignatureData    b.Signature
      SignatureFtlv    a.FTLV
      DeviceFtlv       a.FTLV
      FeatureFtlv      a.FTLV
      KeyInfoFtlv      a.FTLV
      ManufacturerFtlv a.FTLV
      CertificateFtlv  a.FTLV
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
   feature := Feature{
      Entries: 1,
      // SCALABLE with SL2000
      // SUPPORTS_PR3_FEATURES
      Features: []uint32{ 0xD },
   }
   FeatureFtlv.New(1, 5, feature.Encode())
   DeviceFtlv.New(1, 4, NewDevice.Encode())
   leaf_data := CertificateFtlv.Encode()
   leaf_data = append(leaf_data, DeviceFtlv.Encode()...)
   leaf_data = append(leaf_data, FeatureFtlv.Encode()...)
   leaf_data = append(leaf_data, KeyInfoFtlv.Encode()...)
   leaf_data = append(leaf_data, ManufacturerFtlv.Encode()...)
   var UnsignedCert Cert
   UnsignedCert.NewNoSig(leaf_data)
   SignatureDigest := sha256.Sum256(UnsignedCert.Encode())
   r, s, err := ecdsa.Sign(a.Fill, ModelKey.Key, SignatureDigest[:])
   if err != nil {
      return err
   }
   sign := append(r.Bytes(), s.Bytes()...)
   SignatureData.New(sign, ModelKey.PublicBytes())
   SignatureFtlv.New(1, 8, SignatureData.Encode())
   leaf_data = append(leaf_data, SignatureFtlv.Encode()...)
   UnsignedCert.Length = uint32(len(leaf_data)) + 16
   UnsignedCert.RawData = leaf_data
   c.Length += UnsignedCert.Length
   c.CertCount += 1
   c.Certs = slices.Insert(c.Certs, 0, UnsignedCert)
   return nil
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
      var cert1 Cert
      i, err := cert1.Decode(data)
      if err != nil {
         return err
      }
      data = data[i:]
      c.Certs = append(c.Certs, cert1)
   }
   return nil
}

type Feature struct {
   Entries  uint32
   Features []uint32
}

func (f *Feature) New(Type int) {
   f.Entries = 1
   f.Features = []uint32{uint32(Type)}
}

func (f *Feature) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, f.Entries)

   for i := range f.Entries {
      data = binary.BigEndian.AppendUint32(data, f.Features[i])
   }

   return data
}

func (f *Feature) Decode(data []byte) (int, error) {
   f.Entries = binary.BigEndian.Uint32(data)
   var n = 4
   for range f.Entries {
      f.Features = append(f.Features, binary.BigEndian.Uint32(data[n:]))
      n += 4
   }
   return n, nil
}

func (k *Key) New(Key []byte, Type int) {
   k.Type = 1
   k.Length = 512
   copy(k.PublicKey[:], Key)
   k.Usage.New(Type)
}

type Key struct {
   Type      uint16
   Length    uint16
   Flags     uint32
   PublicKey [64]byte
   Usage     Feature
}

func (k *Key) Decode(data []byte) (int, error) {
   k.Type = binary.BigEndian.Uint16(data)
   n := 2
   k.Length = binary.BigEndian.Uint16(data[n:])
   n += 2
   k.Flags = binary.BigEndian.Uint32(data[n:])
   n += 4
   n += copy(k.PublicKey[:], data[n:])
   n1, err := k.Usage.Decode(data[n:])
   if err != nil {
      return 0, err
   }
   n += n1
   return n, nil
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

func (k *KeyInfo) New(SigningKey, EncryptKey []byte) {
   k.Entries = 2
   k.Keys = make([]Key, 2)
   k.Keys[0].New(SigningKey, 1)
   k.Keys[1].New(EncryptKey, 2)
}

type KeyInfo struct {
   Entries uint32
   Keys    []Key
}

func (k *KeyInfo) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, k.Entries)

   for i := range k.Entries {
      data = append(data, k.Keys[i].Encode()...)
   }

   return data
}

func (k *KeyInfo) Decode(data []byte) error {
   k.Entries = binary.BigEndian.Uint32(data)
   data = data[4:]

   for range k.Entries {
      var KeyData Key

      i, err := KeyData.Decode(data)

      if err != nil {
         return err
      }

      k.Keys = append(k.Keys, KeyData)

      data = data[i:]
   }

   return nil
}

type ManufacturerInfo struct {
   Length uint32
   Value  string
}

func (m *ManufacturerInfo) Encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, m.Length)
   return append(data, []byte(m.Value)...)
}

func (m *ManufacturerInfo) Decode(data []byte) (uint32, error) {
   m.Length = binary.BigEndian.Uint32(data)
   var n uint32 = 4
   padded_length := (m.Length + 3) &^ 3
   m.Value = string(data[n:][:padded_length])
   return n + padded_length, nil
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
   return append(data, m.ModelNumber.Encode()...)
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
   // NOTE SOME SERVERS, FOR EXAMPLE
   // rakuten.tv
   // WILL LOCK LICENSE TO THE FIRST DEVICE, USING "ClientId" TO DETECT, SO BE
   // CAREFUL USING A VALUE HERE
   ClientId [16]byte
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

const (
   OBJTYPE_BASIC              = 0x0001
   OBJTYPE_DOMAIN             = 0x0002
   OBJTYPE_PC                 = 0x0003
   OBJTYPE_DEVICE             = 0x0004
   OBJTYPE_FEATURE            = 0x0005
   OBJTYPE_KEY                = 0x0006
   OBJTYPE_MANUFACTURER       = 0x0007
   OBJTYPE_SIGNATURE          = 0x0008
   OBJTYPE_SILVERLIGHT        = 0x0009
   OBJTYPE_METERING           = 0x000A
   OBJTYPE_EXTDATASIGNKEY     = 0x000B
   OBJTYPE_EXTDATACONTAINER   = 0x000C
   OBJTYPE_EXTDATASIGNATURE   = 0x000D
   OBJTYPE_EXTDATA_HWID       = 0x000E
   OBJTYPE_SERVER             = 0x000F
   OBJTYPE_SECURITY_VERSION   = 0x0010
   OBJTYPE_SECURITY_VERSION_2 = 0x0011
)

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
      var ftlv a.FTLV
      j, err := ftlv.Decode(c.RawData[sum:])
      if err != nil {
         return 0, err
      }
      switch ftlv.Type {
      case OBJTYPE_BASIC:
         c.CertificateInfo = &CertInfo{}
         err := c.CertificateInfo.Decode(ftlv.Value)
         if err != nil {
            return 0, err
         }

      case OBJTYPE_FEATURE:
         c.Features = &Feature{}
         _, err := c.Features.Decode(ftlv.Value)
         if err != nil {
            return 0, err
         }

      case OBJTYPE_KEY:
         c.KeyData = &KeyInfo{}
         err := c.KeyData.Decode(ftlv.Value)
         if err != nil {
            return 0, err
         }

      case OBJTYPE_MANUFACTURER:
         c.ManufacturerInfo = &Manufacturer{}
         err := c.ManufacturerInfo.Decode(ftlv.Value)
         if err != nil {
            return 0, err
         }

      case OBJTYPE_SIGNATURE:
         c.SignatureData = &b.Signature{}
         err := c.SignatureData.Decode(ftlv.Value)
         if err != nil {
            return 0, err
         }

      }

      sum += j
   }

   return n, nil
}

type LocalDevice struct {
   CertificateChain Chain
   EncryptKey       a.EcKey
   SigningKey       a.EcKey
}

type Chain struct {
   Magic     [4]byte
   Version   uint32
   Length    uint32
   Flags     uint32
   CertCount uint32
   Certs     []Cert
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
   SignatureData     *b.Signature
}

func (c *Cert) NewNoSig(Value []byte) {
   copy(c.Magic[:], "CERT")
   c.Version = 1
   c.Length = uint32(len(Value)) + 16 + 144
   c.LengthToSignature = uint32(len(Value)) + 16
   c.RawData = make([]byte, len(Value))
   copy(c.RawData, Value)
}

func (c *Chain) Encode() []byte {
   data := c.Magic[:]
   data = binary.BigEndian.AppendUint32(data, c.Version)
   data = binary.BigEndian.AppendUint32(data, c.Length)
   data = binary.BigEndian.AppendUint32(data, c.Flags)
   data = binary.BigEndian.AppendUint32(data, c.CertCount)
   for _, cert1 := range c.Certs {
      data = append(data, cert1.Encode()...)
   }
   return data
}

func (c *Chain) Verify() bool {
   ModelBase := c.Certs[len(c.Certs)-1].SignatureData.IssuerKey
   for i := len(c.Certs) - 1; i >= 0; i-- {
      valid := c.Certs[i].Verify(ModelBase[:])
      if !valid {
         return false
      }
      ModelBase = c.Certs[i].KeyData.Keys[0].PublicKey[:]
   }
   return true
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
func (c *Cert) Encode() []byte {
   data := c.Magic[:]
   data = binary.BigEndian.AppendUint32(data, c.Version)
   data = binary.BigEndian.AppendUint32(data, c.Length)
   data = binary.BigEndian.AppendUint32(data, c.LengthToSignature)
   return append(data, c.RawData[:]...)
}

