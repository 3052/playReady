package playReady

import (
   "41.neocities.org/playReady/certificate"
   "bytes"
   "crypto/ecdsa"
   "crypto/sha256"
   "encoding/base64"
   "encoding/binary"
   "encoding/xml"
   "errors"
   "slices"
)

func (c *Chain) cipher_data(key *XmlKey) ([]byte, error) {
   data1, err := xml.Marshal(Data{
      CertificateChains: CertificateChains{
         CertificateChain: base64.StdEncoding.EncodeToString(c.Encode()),
      },
      Features: Features{
         Feature: Feature{"AESCBC"}, // SCALABLE
      },
   })
   if err != nil {
      return nil, err
   }
   data1, err = aes_cbc_padding_encrypt(data1, key.AesKey[:], key.AesIv[:])
   if err != nil {
      return nil, err
   }
   return append(key.AesIv[:], data1...), nil
}

func (c *Chain) CreateLeaf(ModelKey, SigningKey, EncryptKey EcKey) error {
   if !bytes.Equal(c.Certs[0].KeyData.Keys[0].PublicKey[:], ModelKey.PublicBytes()) {
      return errors.New("zgpriv not for cert")
   }
   if !c.Verify() {
      return errors.New("cert is not valid")
   }
   var (
      BuiltKeyInfo     certificate.KeyInfo
      CertificateInfo  CertInfo
      SignatureData    certificate.Signature
      SignatureFtlv    FTLV
      DeviceFtlv       FTLV
      FeatureFtlv      FTLV
      KeyInfoFtlv      FTLV
      ManufacturerFtlv FTLV
      CertificateFtlv  FTLV
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
   // SCALABLE with SL2000 /////////////////////////////////////////////
   feature := c.Certs[0].Features
   feature.Entries++
   feature.Features = append(feature.Features, 13)
   c.Certs[0].Features = feature
   ///////////////////////////////////////////////////////////////////////
   FeatureFtlv.New(1, 5, c.Certs[0].Features.Encode())
   DeviceFtlv.New(1, 4, NewDevice.Encode())
   leaf_data := CertificateFtlv.Encode()
   leaf_data = append(leaf_data, DeviceFtlv.Encode()...)
   leaf_data = append(leaf_data, FeatureFtlv.Encode()...)
   leaf_data = append(leaf_data, KeyInfoFtlv.Encode()...)
   leaf_data = append(leaf_data, ManufacturerFtlv.Encode()...)
   var UnsignedCert Cert
   UnsignedCert.NewNoSig(leaf_data)
   SignatureDigest := sha256.Sum256(UnsignedCert.Encode())
   r, s, err := ecdsa.Sign(Fill, ModelKey.Key, SignatureDigest[:])
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

type Chain struct {
   Magic     [4]byte
   Version   uint32
   Length    uint32
   Flags     uint32
   CertCount uint32
   Certs     []Cert
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
