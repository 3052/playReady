package playReady

import (
   "bytes"
   "crypto/ecdsa"
   "crypto/sha256"
   "encoding/base64"
   "encoding/binary"
   "encoding/hex"
   "encoding/xml"
   "errors"
)

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
