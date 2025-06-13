package playReady

import (
   "41.neocities.org/playReady/certificate"
   "41.neocities.org/playReady/license"
   "bytes"
   "crypto/aes"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/sha256"
   "encoding/base64"
   "encoding/binary"
   "encoding/hex"
   "encoding/xml"
   "errors"
   "fmt"
   "github.com/deatil/go-cryptobin/cryptobin/crypto"
   "github.com/deatil/go-cryptobin/mac"
   "math/big"
   "slices"
)

type LicenseResponse struct {
   RawData          []byte
   Magic            [4]byte
   Offset           uint16
   Version          uint16
   RightsId         [16]byte
   OuterContainer   FTLV
   ContentKeyObject *ContentKey
   ECCKeyObject     *ECCKey
   SignatureObject  *license.Signature
   AuxKeyObject     *AuxKeys
}

func (l *LicenseResponse) Verify(content_integrity []byte) error {
   data := l.Encode()
   data = data[:len(l.RawData)-int(l.SignatureObject.Length)]
   block, err := aes.NewCipher(content_integrity)
   if err != nil {
      return err
   }
   data = mac.NewCMAC(block, aes.BlockSize).MAC(data)
   if !bytes.Equal(data, l.SignatureObject.Data) {
      return errors.New("failed to decrypt the keys")
   }
   return nil
}

func (l *LicenseResponse) Decode(data []byte) error {
   l.RawData = make([]byte, len(data))
   copy(l.RawData, data)

   n := copy(l.Magic[:], data)
   l.Offset = binary.BigEndian.Uint16(data[n:])
   n += 2
   l.Version = binary.BigEndian.Uint16(data[n:])
   n += 2
   n += copy(l.RightsId[:], data[n:])

   j, err := l.OuterContainer.Decode(data[n:])

   if err != nil {
      return err
   }
   n += int(j)

   var size uint32

   for size < l.OuterContainer.Length-16 {
      var ftlv FTLV
      i, err := ftlv.Decode(l.OuterContainer.Value[int(size):])
      if err != nil {
         return err
      }
      switch XmrType(ftlv.Type) {
      case GLOBAL_POLICY_CONTAINER_ENTRY_TYPE: // 2
         // Rakuten
      case PLAYBACK_POLICY_CONTAINER_ENTRY_TYPE: // 4
         // Rakuten
      case KEY_MATERIAL_CONTAINER_ENTRY_TYPE: // 9
         var j uint32
         for j < ftlv.Length-16 {
            var ftlv2 FTLV
            k, err := ftlv2.Decode(ftlv.Value[j:])
            if err != nil {
               return err
            }
            switch XmrType(ftlv2.Type) {
            case CONTENT_KEY_ENTRY_TYPE: // 10
               l.ContentKeyObject = &ContentKey{}
               err = l.ContentKeyObject.Decode(ftlv2.Value)
               if err != nil {
                  return err
               }
            case DEVICE_KEY_ENTRY_TYPE: // 42
               l.ECCKeyObject = &ECCKey{}
               err = l.ECCKeyObject.Decode(ftlv2.Value)
               if err != nil {
                  return err
               }
            case AUX_KEY_ENTRY_TYPE: // 81
               l.AuxKeyObject = &AuxKeys{}
               err = l.AuxKeyObject.Decode(ftlv2.Value)
               if err != nil {
                  return err
               }
            default:
               return errors.New("ftlv2.Type")
            }
            j += k
         }
      case SIGNATURE_ENTRY_TYPE: // 11
         l.SignatureObject = &license.Signature{}
         err := l.SignatureObject.Decode(ftlv.Value)
         l.SignatureObject.Length = uint16(ftlv.Length)
         if err != nil {
            return err
         }
      default:
         return errors.New("ftlv.Type")
      }
      size += i
   }

   return nil
}

func (l *LicenseResponse) Encode() []byte {
   data := l.Magic[:]
   data = binary.BigEndian.AppendUint16(data, l.Offset)
   data = binary.BigEndian.AppendUint16(data, l.Version)
   data = append(data, l.RightsId[:]...)

   data = append(data, l.OuterContainer.Encode()...)
   return data
}

func (l *LicenseResponse) Parse(data string) error {
   decoded, err := base64.StdEncoding.DecodeString(data)

   if err != nil {
      return err
   }
   return l.Decode(decoded)
}
func XorKey(root, second []byte) []byte {
   data := make([]byte, len(second))
   copy(data, root)
   for i := range 16 {
      data[i] ^= second[i]
   }
   return data
}

func (c *ContentKey) ECC256(key EcKey) []byte {
   var el_gamal ElGamal
   return el_gamal.Decrypt(c.Value, key.Key.D)
}

func (c *ContentKey) Decode(data []byte) error {
   c.KeyId.Decode(data[:])
   data = data[16:]
   c.KeyType = binary.BigEndian.Uint16(data)
   data = data[2:]

   c.CipherType = binary.BigEndian.Uint16(data)
   data = data[2:]

   c.Length = binary.BigEndian.Uint16(data)
   data = data[2:]

   c.Value = make([]byte, c.Length)

   copy(c.Value[:], data)

   return nil
}

func (c *ContentKey) Decrypt(key EcKey, aux_keys *AuxKeys) error {
   switch c.CipherType {
   case 3:
      decrypted := c.ECC256(key)
      c.Integrity.Decode(decrypted)
      decrypted = decrypted[16:]
      copy(c.Key[:], decrypted)
      return nil
   case 6:
      return c.Scalable(key, aux_keys)
   }
   return errors.New("cant decrypt key")
}

func (c *ContentKey) Scalable(key EcKey, aux_keys *AuxKeys) error {
   rootKeyInfo := c.Value[:144]
   root_key := rootKeyInfo[128:]
   leaf_keys := c.Value[144:]
   var el_gamal ElGamal
   decrypted := el_gamal.Decrypt(rootKeyInfo[:128], key.Key.D)
   var (
      CI [16]byte
      CK [16]byte
   )
   for i := range 16 {
      CI[i] = decrypted[i*2]
      CK[i] = decrypted[i*2+1]
   }
   magic_constant_zero, err := hex.DecodeString("7ee9ed4af773224f00b8ea7efb027cbb")
   if err != nil {
      return err
   }
   rgb_uplink_xkey := XorKey(CK[:], magic_constant_zero)
   content_key_prime, err := aes_ecb_encrypt(rgb_uplink_xkey, CK[:])
   if err != nil {
      return err
   }
   aux_key_calc, err := aes_ecb_encrypt(
      aux_keys.Keys[0].Key[:], content_key_prime,
   )
   if err != nil {
      return err
   }
   var zero [16]byte
   up_link_xkey := XorKey(aux_key_calc, zero[:])
   o_secondary_key, err := aes_ecb_encrypt(root_key, CK[:])
   if err != nil {
      return err
   }
   rgb_key, err := aes_ecb_encrypt(leaf_keys, up_link_xkey)
   if err != nil {
      return err
   }
   rgb_key, err = aes_ecb_encrypt(rgb_key, o_secondary_key)
   if err != nil {
      return err
   }
   c.Integrity.Decode(rgb_key[:])
   rgb_key = rgb_key[16:]
   copy(c.Key[:], rgb_key)
   return nil
}

type ContentKey struct {
   KeyId      Guid
   KeyType    uint16
   CipherType uint16
   Length     uint16
   Value      []byte
   Integrity  Guid
   Key        [16]byte
}

type LocalDevice struct {
   CertificateChain Chain
   EncryptKey       EcKey
   SigningKey       EcKey
}

func (ld *LocalDevice) ParseLicense(data []byte) (*KeyData, error) {
   var response EnvelopeResponse
   err := xml.Unmarshal(data, &response)
   if err != nil {
      return nil, err
   }
   if fault := response.Body.Fault; fault != nil {
      return nil, errors.New(fault.Fault)
   }
   var license LicenseResponse
   err = license.Parse(response.
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
   if !bytes.Equal(license.ECCKeyObject.Value, ld.EncryptKey.PublicBytes()) {
      return nil, errors.New("license response is not for this device")
   }
   err = license.ContentKeyObject.Decrypt(ld.EncryptKey, license.AuxKeyObject)
   if err != nil {
      return nil, err
   }
   err = license.Verify(license.ContentKeyObject.Integrity.Guid())
   if err != nil {
      return nil, err
   }
   return &KeyData{
      license.ContentKeyObject.KeyId, license.ContentKeyObject.Key,
   }, nil
}
type Reference struct {
   Uri         string `xml:"URI,attr"`
   DigestValue string
}

type Signature struct {
   SignedInfo     SignedInfo
   SignatureValue string
}

type SignedInfo struct {
   XmlNs     string `xml:"xmlns,attr"`
   Reference Reference
}

type EnvelopeResponse struct {
   Body Body
}

type AcquireLicense struct {
   XmlNs     string    `xml:"xmlns,attr"`
   Challenge Challenge `xml:"challenge"`
}

type Challenge struct {
   Challenge InnerChallenge
}

type InnerChallenge struct { // Renamed from Challenge
   XmlNs     string `xml:"xmlns,attr"`
   La        La
   Signature Signature
}

type La struct {
   XMLName       xml.Name `xml:"LA"`
   XmlNs         string   `xml:"xmlns,attr"`
   Id            string   `xml:"Id,attr"`
   Version       string
   ContentHeader ContentHeader
   EncryptedData EncryptedData
}

type ContentHeader struct {
   WrmHeader WrmHeader `xml:"WRMHEADER"`
}

type Algorithm struct {
   Algorithm string `xml:"Algorithm,attr"`
}

type CipherData struct {
   CipherValue string
}

type EncryptedData struct {
   XmlNs            string `xml:"xmlns,attr"`
   Type             string `xml:"Type,attr"`
   EncryptionMethod Algorithm
   KeyInfo          KeyInfo
   CipherData       CipherData
}

type WrmHeader struct {
   XmlNs   string        `xml:"xmlns,attr"`
   Version string        `xml:"version,attr"`
   Data    WrmHeaderData `xml:"DATA"`
}

type KeyInfo struct { // This is the chosen "KeyInfo" type
   XmlNs        string `xml:"xmlns,attr"`
   EncryptedKey EncryptedKey
}

type ProtectInfo struct {
   KeyLen string `xml:"KEYLEN"`
   AlgId  string `xml:"ALGID"`
}

type WrmHeaderData struct { // Renamed from DATA
   ProtectInfo ProtectInfo `xml:"PROTECTINFO"`
   Kid         string      `xml:"KID"`
}

type EncryptedKeyInfo struct { // Renamed from KeyInfo
   XmlNs   string `xml:"xmlns,attr"`
   KeyName string
}

type EncryptedKey struct {
   XmlNs            string `xml:"xmlns,attr"`
   EncryptionMethod Algorithm
   KeyInfo          EncryptedKeyInfo
   CipherData       CipherData
}

type Body struct {
   AcquireLicense         *AcquireLicense
   AcquireLicenseResponse *struct {
      AcquireLicenseResult struct {
         Response struct {
            LicenseResponse struct {
               Licenses struct {
                  License string
               }
            }
         }
      }
   }
   Fault *struct {
      Fault string `xml:"faultstring"`
   }
}

func (v *La) New(key *XmlKey, cipher_data []byte, kid string) error {
   var ecc_pub_key WMRM
   x, y, err := ecc_pub_key.Points()
   if err != nil {
      return err
   }
   var el_gamal ElGamal
   encrypted, err := el_gamal.Encrypt(x, y, key)
   if err != nil {
      return err
   }
   *v = La{
      XmlNs:   "http://schemas.microsoft.com/DRM/2007/03/protocols",
      Id:      "SignedData",
      Version: "1",
      ContentHeader: ContentHeader{
         WrmHeader: WrmHeader{
            XmlNs:   "http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader",
            Version: "4.0.0.0",
            Data: WrmHeaderData{
               ProtectInfo: ProtectInfo{
                  KeyLen: "16",
                  AlgId:  "AESCTR",
               },
               Kid: kid,
            },
         },
      },
      EncryptedData: EncryptedData{
         XmlNs: "http://www.w3.org/2001/04/xmlenc#",
         Type:  "http://www.w3.org/2001/04/xmlenc#Element",
         EncryptionMethod: Algorithm{
            Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
         },
         KeyInfo: KeyInfo{
            XmlNs: "http://www.w3.org/2000/09/xmldsig#",
            EncryptedKey: EncryptedKey{
               XmlNs: "http://www.w3.org/2001/04/xmlenc#",
               EncryptionMethod: Algorithm{
                  Algorithm: "http://schemas.microsoft.com/DRM/2007/03/protocols#ecc256",
               },
               KeyInfo: EncryptedKeyInfo{
                  XmlNs:   "http://www.w3.org/2000/09/xmldsig#",
                  KeyName: "WMRMServer",
               },
               CipherData: CipherData{
                  CipherValue: base64.StdEncoding.EncodeToString(encrypted),
               },
            },
         },
         CipherData: CipherData{
            CipherValue: base64.StdEncoding.EncodeToString(cipher_data),
         },
      },
   }
   return nil
}

type Envelope struct {
   XMLName xml.Name `xml:"soap:Envelope"`
   Soap    string   `xml:"xmlns:soap,attr"`
   Body    Body     `xml:"soap:Body"`
}

func (v *LocalDevice) envelope(kid string) (*Envelope, error) {
   var key XmlKey
   err := key.New()
   if err != nil {
      return nil, err
   }
   cipher_data, err := v.CertificateChain.cipher_data(&key)
   if err != nil {
      return nil, err
   }
   var la_value La
   err = la_value.New(&key, cipher_data, kid)
   if err != nil {
      return nil, err
   }
   la_data, err := xml.Marshal(la_value)
   if err != nil {
      return nil, err
   }
   la_digest := sha256.Sum256(la_data)
   signed_info := SignedInfo{
      XmlNs: "http://www.w3.org/2000/09/xmldsig#",
      Reference: Reference{
         Uri:         "#SignedData",
         DigestValue: base64.StdEncoding.EncodeToString(la_digest[:]),
      },
   }
   signed_data, err := xml.Marshal(signed_info)
   if err != nil {
      return nil, err
   }
   signed_digest := sha256.Sum256(signed_data)
   r, s, err := ecdsa.Sign(Fill, v.SigningKey.Key, signed_digest[:])
   if err != nil {
      return nil, err
   }
   sign := append(r.Bytes(), s.Bytes()...)
   return &Envelope{
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
                     SignatureValue: base64.StdEncoding.EncodeToString(sign),
                  },
               },
            },
         },
      },
   }, nil
}

type Features struct {
   Feature Feature
}

type Feature struct {
   Name string `xml:",attr"`
}

type Data struct {
   CertificateChains CertificateChains
   Features          Features
}
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
   feature := certificate.Feature{
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
func (c *Cert) NewNoSig(Value []byte) {
   copy(c.Magic[:], "CERT")
   c.Version = 1
   c.Length = uint32(len(Value)) + 16 + 144
   c.LengthToSignature = uint32(len(Value)) + 16
   c.RawData = make([]byte, len(Value))
   copy(c.RawData, Value)
}

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
      var value FTLV
      j, err := value.Decode(c.RawData[sum:])
      if err != nil {
         return 0, err
      }
      switch value.Type {
      case OBJTYPE_BASIC:
         c.CertificateInfo = &CertInfo{}
         err := c.CertificateInfo.Decode(value.Value)
         if err != nil {
            return 0, err
         }

      case OBJTYPE_FEATURE:
         c.Features = &certificate.Feature{}
         _, err := c.Features.Decode(value.Value)
         if err != nil {
            return 0, err
         }

      case OBJTYPE_KEY:
         c.KeyData = &certificate.KeyInfo{}
         err := c.KeyData.Decode(value.Value)
         if err != nil {
            return 0, err
         }

      case OBJTYPE_MANUFACTURER:
         c.ManufacturerInfo = &Manufacturer{}
         err := c.ManufacturerInfo.Decode(value.Value)
         if err != nil {
            return 0, err
         }

      case OBJTYPE_SIGNATURE:
         c.SignatureData = &certificate.Signature{}
         err := c.SignatureData.Decode(value.Value)

         if err != nil {
            return 0, err
         }

      }

      sum += j
   }

   return n, nil
}

func (c *Cert) Encode() []byte {
   data := c.Magic[:]
   data = binary.BigEndian.AppendUint32(data, c.Version)
   data = binary.BigEndian.AppendUint32(data, c.Length)
   data = binary.BigEndian.AppendUint32(data, c.LengthToSignature)
   return append(data, c.RawData[:]...)
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

func (e *EcKey) New() error {
   var err error
   e.Key, err = ecdsa.GenerateKey(elliptic.P256(), Fill)
   if err != nil {
      return err
   }
   return nil
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

type XmrType uint16

const (
   OUTER_CONTAINER_ENTRY_TYPE                   XmrType = 1
   GLOBAL_POLICY_CONTAINER_ENTRY_TYPE           XmrType = 2
   PLAYBACK_POLICY_CONTAINER_ENTRY_TYPE         XmrType = 4
   MINIMUM_OUTPUT_PROTECTION_LEVELS_ENTRY_TYPE  XmrType = 5
   EXPLICIT_ANALOG_VIDEO_PROTECTION_ENTRY_TYPE  XmrType = 7
   ANALOG_VIDEO_OPL_ENTRY_TYPE                  XmrType = 8
   KEY_MATERIAL_CONTAINER_ENTRY_TYPE            XmrType = 9
   CONTENT_KEY_ENTRY_TYPE                       XmrType = 10
   SIGNATURE_ENTRY_TYPE                         XmrType = 11
   SERIAL_NUMBER_ENTRY_TYPE                     XmrType = 12
   RIGHTS_ENTRY_TYPE                            XmrType = 13
   EXPIRATION_ENTRY_TYPE                        XmrType = 18
   ISSUEDATE_ENTRY_TYPE                         XmrType = 19
   METERING_ENTRY_TYPE                          XmrType = 22
   GRACEPERIOD_ENTRY_TYPE                       XmrType = 26
   SOURCEID_ENTRY_TYPE                          XmrType = 34
   RESTRICTED_SOURCEID_ENTRY_TYPE               XmrType = 40
   DOMAIN_ID_ENTRY_TYPE                         XmrType = 41
   DEVICE_KEY_ENTRY_TYPE                        XmrType = 42
   POLICY_METADATA_ENTRY_TYPE                   XmrType = 44
   OPTIMIZED_CONTENT_KEY_ENTRY_TYPE             XmrType = 45
   EXPLICIT_DIGITAL_AUDIO_PROTECTION_ENTRY_TYPE XmrType = 46
   EXPIRE_AFTER_FIRST_USE_ENTRY_TYPE            XmrType = 48
   DIGITAL_AUDIO_OPL_ENTRY_TYPE                 XmrType = 49
   REVOCATION_INFO_VERSION_ENTRY_TYPE           XmrType = 50
   EMBEDDING_BEHAVIOR_ENTRY_TYPE                XmrType = 51
   SECURITY_LEVEL_ENTRY_TYPE                    XmrType = 52
   MOVE_ENABLER_ENTRY_TYPE                      XmrType = 55
   UPLINK_KID_ENTRY_TYPE                        XmrType = 59
   COPY_POLICIES_CONTAINER_ENTRY_TYPE           XmrType = 60
   COPY_COUNT_ENTRY_TYPE                        XmrType = 61
   REMOVAL_DATE_ENTRY_TYPE                      XmrType = 80
   AUX_KEY_ENTRY_TYPE                           XmrType = 81
   UPLINKX_ENTRY_TYPE                           XmrType = 82
   REAL_TIME_EXPIRATION_ENTRY_TYPE              XmrType = 85
   EXPLICIT_DIGITAL_VIDEO_PROTECTION_ENTRY_TYPE XmrType = 88
   DIGITAL_VIDEO_OPL_ENTRY_TYPE                 XmrType = 89
   SECURESTOP_ENTRY_TYPE                        XmrType = 90
   COPY_UNKNOWN_OBJECT_ENTRY_TYPE               XmrType = 65533
   GLOBAL_POLICY_UNKNOWN_OBJECT_ENTRY_TYPE      XmrType = 65533
   PLAYBACK_UNKNOWN_OBJECT_ENTRY_TYPE           XmrType = 65533
   COPY_UNKNOWN_CONTAINER_ENTRY_TYPE            XmrType = 65534
   UNKNOWN_CONTAINERS_ENTRY_TYPE                XmrType = 65534
   PLAYBACK_UNKNOWN_CONTAINER_ENTRY_TYPE        XmrType = 65534
)

type KeyData struct {
   KeyId Guid
   Key   [16]byte
}

type Guid struct {
   Data1 uint32 // little endian
   Data2 uint16 // little endian
   Data3 uint16 // little endian
   Data4 uint64 // big endian
}

func (k *Guid) Uuid() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, k.Data1)
   data = binary.BigEndian.AppendUint16(data, k.Data2)
   data = binary.BigEndian.AppendUint16(data, k.Data3)
   return binary.BigEndian.AppendUint64(data, k.Data4)
}

func (k *Guid) Guid() []byte {
   var data []byte
   data = binary.LittleEndian.AppendUint32(data, k.Data1)
   data = binary.LittleEndian.AppendUint16(data, k.Data2)
   data = binary.LittleEndian.AppendUint16(data, k.Data3)
   return binary.BigEndian.AppendUint64(data, k.Data4)
}

func (k *Guid) Decode(data []byte) {
   k.Data1 = binary.LittleEndian.Uint32(data)
   data = data[4:]
   k.Data2 = binary.LittleEndian.Uint16(data)
   data = data[2:]
   k.Data3 = binary.LittleEndian.Uint16(data)
   data = data[2:]
   k.Data4 = binary.BigEndian.Uint64(data)
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

func aes_ecb_encrypt(data, key []byte) ([]byte, error) {
   bin := crypto.FromBytes(data).WithKey(key).
      Aes().ECB().NoPadding().Encrypt()
   return bin.ToBytes(), bin.Error()
}

func aes_cbc_padding_encrypt(data, key, iv []byte) ([]byte, error) {
   bin := crypto.FromBytes(data).WithKey(key).WithIv(iv).
      Aes().CBC().PKCS7Padding().Encrypt()
   return bin.ToBytes(), bin.Error()
}

func (e *EcKey) LoadBytes(data []byte) {
   var public ecdsa.PublicKey
   public.Curve = elliptic.P256()
   public.X, public.Y = public.Curve.ScalarBaseMult(data)
   var private ecdsa.PrivateKey
   private.D = new(big.Int).SetBytes(data)
   private.PublicKey = public
   e.Key = &private
}

func (e *EcKey) PublicBytes() []byte {
   SigningX, SigningY := e.Key.PublicKey.X.Bytes(), e.Key.PublicKey.Y.Bytes()
   SigningPublicKey := SigningX
   SigningPublicKey = append(SigningPublicKey, SigningY...)
   return SigningPublicKey
}

func (e EcKey) Private() []byte {
   var data [32]byte
   e.Key.D.FillBytes(data[:])
   return data[:]
}

type EcKey struct {
   Key *ecdsa.PrivateKey
}

type AuxKeys struct {
   Count uint16
   Keys  []AuxKey
}

func (a *AuxKeys) Decode(data []byte) error {
   a.Count = binary.BigEndian.Uint16(data)
   data = data[2:]

   for range a.Count {
      var Key AuxKey

      i, err := Key.Decode(data)

      if err != nil {
         return err
      }

      a.Keys = append(a.Keys, Key)

      data = data[i:]
   }
   return nil
}

func (f *FTLV) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint16(data, f.Flags)
   data = binary.BigEndian.AppendUint16(data, f.Type)
   data = binary.BigEndian.AppendUint32(data, f.Length)
   return append(data, f.Value...)
}

func (f *FTLV) Decode(data []byte) (uint32, error) {
   var n uint32
   f.Flags = binary.BigEndian.Uint16(data[n:])
   n += 2
   f.Type = binary.BigEndian.Uint16(data[n:])
   n += 2
   f.Length = binary.BigEndian.Uint32(data[n:])
   n += 4
   f.Value = data[n:][:f.Length-8]
   n += f.Length - 8
   return n, nil
}

type FTLV struct {
   Flags  uint16
   Type   uint16
   Length uint32
   Value  []byte
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

type AuxKey struct {
   Location uint32
   Key      [16]byte
}

func (a *AuxKey) Decode(data []byte) (int, error) {
   a.Location = binary.BigEndian.Uint32(data)
   data = data[4:]

   n := copy(a.Key[:], data)

   return n + 4, nil
}

type ECCKey struct {
   Curve  uint16
   Length uint16
   Value  []byte
}

func (e *ECCKey) Decode(data []byte) error {
   e.Curve = binary.BigEndian.Uint16(data)
   data = data[2:]

   e.Length = binary.BigEndian.Uint16(data)
   data = data[2:]

   e.Value = make([]byte, e.Length)
   copy(e.Value, data)

   return nil
}

type CertificateChains struct {
   CertificateChain string
}

type XmlKey struct {
   AesIv     [16]byte
   AesKey    [16]byte
   PublicKey ecdsa.PublicKey
}

func (WMRM) Points() (*big.Int, *big.Int, error) {
   bytes, err := hex.DecodeString(WMRMPublicKey)
   if err != nil {
      return nil, nil, fmt.Errorf("decoding hex string: %v", err)
   }
   x := new(big.Int).SetBytes(bytes[:32])
   y := new(big.Int).SetBytes(bytes[32:])
   return x, y, nil
}

type ElGamal struct{}

func (ElGamal) Decrypt(ciphertext []byte, PrivateKey *big.Int) []byte {
   curveData := elliptic.P256()

   x1, y1 := new(big.Int).SetBytes(ciphertext[:32]), new(big.Int).SetBytes(ciphertext[32:64])
   x2, y2 := new(big.Int).SetBytes(ciphertext[64:96]), new(big.Int).SetBytes(ciphertext[96:128])

   SX, SY := curveData.ScalarMult(x1, y1, PrivateKey.Bytes())

   NegSY := new(big.Int).Sub(curveData.Params().P, SY)

   NegSY.Mod(NegSY, curveData.Params().P)

   PX, PY := curveData.Add(x2, y2, SX, NegSY)

   Decrypted := PX.Bytes()

   return append(Decrypted, PY.Bytes()...)
}

type WMRM struct{}

var WMRMPublicKey = "C8B6AF16EE941AADAA5389B4AF2C10E356BE42AF175EF3FACE93254E7B0B3D9B982B27B5CB2341326E56AA857DBFD5C634CE2CF9EA74FCA8F2AF5957EFEEA562"

func (ElGamal) Encrypt(
   PubX *big.Int, PubY *big.Int, plaintext *XmlKey,
) ([]byte, error) {
   curveData := elliptic.P256()
   curve_int := big.NewInt(1)
   C1X, C1Y := curveData.ScalarMult(
      curveData.Params().Gx, curveData.Params().Gy, curve_int.Bytes(),
   )
   C2XMulti, C2YMulti := curveData.ScalarMult(PubX, PubY, curve_int.Bytes())
   C2X, C2Y := curveData.Add(
      plaintext.PublicKey.X, plaintext.PublicKey.Y, C2XMulti, C2YMulti,
   )
   Encrypted := C1X.Bytes()
   Encrypted = append(Encrypted, C1Y.Bytes()...)
   Encrypted = append(Encrypted, C2X.Bytes()...)
   return append(Encrypted, C2Y.Bytes()...), nil
}

type Device struct {
   MaxLicenseSize       uint32
   MaxHeaderSize        uint32
   MaxLicenseChainDepth uint32
}

func (d *Device) New() {
   d.MaxLicenseSize = uint32(10240)
   d.MaxHeaderSize = uint32(15360)
   d.MaxLicenseChainDepth = uint32(2)
}

func (d *Device) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, d.MaxLicenseSize)
   data = binary.BigEndian.AppendUint32(data, d.MaxHeaderSize)
   return binary.BigEndian.AppendUint32(data, d.MaxLicenseChainDepth)
}

func (f *FTLV) New(Flags, Type int, Value []byte) {
   f.Flags = uint16(Flags)
   f.Type = uint16(Type)
   f.Length = uint32(len(Value) + 8)
   f.Value = Value
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

type PlayReadyObject struct {
   Type   uint16
   Length uint16
   Data   string
}

func (p *PlayReadyRecord) Decode(data []byte) bool {
   p.Length = binary.LittleEndian.Uint32(data)
   if int(p.Length) > len(data) {
      return false
   }
   data = data[4:]
   p.Count = binary.LittleEndian.Uint16(data)
   data = data[2:]
   p.Data = data
   return true
}

type PlayReadyRecord struct {
   Length uint32
   Count  uint16
   Data   []byte
}
