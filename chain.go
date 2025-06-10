package playReady

import (
   "41.neocities.org/playReady/certificate"
   "bytes"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/sha256"
   "encoding/base64"
   "encoding/binary"
   "encoding/xml"
   "errors"
   "slices"
)

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
func get_cipher_data(
   cert_chain *Chain, key *XmlKey,
) ([]byte, error) {
   data1, err := xml.Marshal(Data{
      CertificateChains: CertificateChains{
         CertificateChain: base64.StdEncoding.EncodeToString(cert_chain.Encode()),
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

type Chain struct {
   Magic     [4]byte
   Version   uint32
   Length    uint32
   Flags     uint32
   CertCount uint32
   Certs     []Cert
}

type Filler byte

// github.com/golang/go/issues/58454
func (f Filler) Read(data []byte) (int, error) {
   for index := range data {
      data[index] = byte(f)
   }
   return len(data), nil
}

var Fill Filler = '!'

///

func (e *EcKey) New() error {
   var err error
   e.Key, err = ecdsa.GenerateKey(elliptic.P256(), Fill)
   if err != nil {
      return err
   }
   return nil
}

func (x *XmlKey) New() error {
   key, err := ecdsa.GenerateKey(elliptic.P256(), Fill)
   if err != nil {
      return err
   }
   x.PublicKey = key.PublicKey
   Aes := x.PublicKey.X.Bytes()
   n := copy(x.AesIv[:], Aes)
   Aes = Aes[n:]
   copy(x.AesKey[:], Aes)
   return nil
}

func (e *Envelope) New(
   cert_chain *Chain, signing_key EcKey, kid string,
) error {
   var key XmlKey
   err := key.New()
   if err != nil {
      return err
   }
   cipher_data, err := get_cipher_data(cert_chain, &key)
   if err != nil {
      return err
   }
   var la_value La
   err = la_value.New(&key, cipher_data, kid)
   if err != nil {
      return err
   }
   la_data, err := xml.Marshal(la_value)
   if err != nil {
      return err
   }
   la_digest := sha256.Sum256(la_data)
   var signed_info SignedInfo
   signed_info.New(la_digest[:])
   signed_data, err := xml.Marshal(signed_info)
   if err != nil {
      return err
   }
   signed_digest := sha256.Sum256(signed_data)
   r, s, err := ecdsa.Sign(Fill, signing_key.Key, signed_digest[:])
   if err != nil {
      return err
   }
   sig := append(r.Bytes(), s.Bytes()...)
   *e = Envelope{
      Soap: "http://schemas.xmlsoap.org/soap/envelope/",
      Body: Body{
         AcquireLicense: &AcquireLicense{
            XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols",
            Challenge: Challenge{
               Challenge: InnerChallenge{
                  XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols/messages",
                  La:    la_value,
                  Signature: Signature{
                     SignedInfo:     signed_info,
                     SignatureValue: base64.StdEncoding.EncodeToString(sig),
                  },
               },
            },
         },
      },
   }
   return nil
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
