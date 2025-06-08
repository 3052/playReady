package playReady

import (
   "41.neocities.org/playReady/certificate"
   "bytes"
   "crypto/ecdsa"
   "crypto/sha256"
   "encoding/binary"
   "encoding/xml"
   "errors"
   "os"
   "slices"
)

type LocalDevice struct {
   CertificateChain       Chain
   SigningKey, EncryptKey EcKey
   Version                string
}

type Chain struct {
   Magic     [4]byte
   Version   uint32
   Length    uint32
   Flags     uint32
   CertCount uint32
   Certs     []Cert
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
   r, s, err := ecdsa.Sign(Fill, ModelKey.Key, SignatureDigest[:])
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

func (c *Chain) LoadFile(path string) error {
   data, err := os.ReadFile(path)
   if err != nil {
      return err
   }
   return c.Decode(data)
}

func (ld *LocalDevice) ParseLicense(response string) (*KeyData, error) {
   var envelope struct {
      Body struct {
         AcquireLicenseResponse struct {
            AcquireLicenseResult struct {
               Response struct {
                  LicenseResponse struct {
                     Licenses struct { License string }
                  }
               }
            }
         }
      }
   }
   err := xml.Unmarshal([]byte(response), &envelope)
   if err != nil {
      return nil, err
   }
   var license1 LicenseResponse
   err = license1.Parse(
      envelope.
         Body.
         AcquireLicenseResponse.
         AcquireLicenseResult.
         Response.
         LicenseResponse.
         Licenses.
         License,
   )
   if err != nil {
      return nil, err
   }
   if !bytes.Equal(license1.ECCKeyObject.Value, ld.EncryptKey.PublicBytes()) {
      return nil, errors.New("license response is not for this device")
   }
   err = license1.ContentKeyObject.Decrypt(ld.EncryptKey, license1.AuxKeyObject)
   if err != nil {
      return nil, err
   }
   err = license1.Verify(license1.ContentKeyObject.Integrity.Bytes())
   if err != nil {
      return nil, err
   }
   return &KeyData{
      license1.ContentKeyObject.KeyId, license1.ContentKeyObject.Key,
   }, nil
}
type Config struct {
   Version    string `json:"client_version"`
   CertChain  string `json:"cert_chain"`
   SigningKey string `json:"signing"`
   EncryptKey string `json:"encrypt"`
}

func (ld *LocalDevice) New(CertChain, EncryptionKey, SigningKey []byte, ClientVersion string) error {
   err := ld.CertificateChain.Decode(CertChain)
   if err != nil {
      return err
   }
   ld.EncryptKey.LoadBytes(EncryptionKey)
   ld.SigningKey.LoadBytes(SigningKey)
   ld.Version = ClientVersion
   return nil
}

type KeyData struct {
   KeyId Guid
   Key   Guid
}

