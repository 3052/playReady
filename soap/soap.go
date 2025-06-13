package soap

import (
   "41.neocities.org/playReady/a"
   "41.neocities.org/playReady/c"
   "bytes"
   "crypto/ecdsa"
   "crypto/sha256"
   "encoding/base64"
   "encoding/xml"
   "errors"
)

func ParseLicense(device *c.LocalDevice, data []byte) (*a.ContentKey, error) {
   var response EnvelopeResponse
   err := xml.Unmarshal(data, &response)
   if err != nil {
      return nil, err
   }
   if fault := response.Body.Fault; fault != nil {
      return nil, errors.New(fault.Fault)
   }
   decoded, err := base64.StdEncoding.DecodeString(response.
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
   var license a.LicenseResponse
   err = license.Decode(decoded)
   if err != nil {
      return nil, err
   }
   if !bytes.Equal(license.ECCKeyObject.Value, device.EncryptKey.PublicBytes()) {
      return nil, errors.New("license response is not for this device")
   }
   err = license.ContentKeyObject.Decrypt(device.EncryptKey, license.AuxKeyObject)
   if err != nil {
      return nil, err
   }
   err = license.Verify(license.ContentKeyObject.Integrity.Guid())
   if err != nil {
      return nil, err
   }
   return license.ContentKeyObject, nil
}

func get_cipher_data(chain *c.Chain, key *a.XmlKey) ([]byte, error) {
   data1, err := xml.Marshal(Data{
      CertificateChains: CertificateChains{
         CertificateChain: base64.StdEncoding.EncodeToString(chain.Encode()),
      },
      Features: Features{
         Feature: Feature{"AESCBC"}, // SCALABLE
      },
   })
   if err != nil {
      return nil, err
   }
   data1, err = a.AesCbcPaddingEncrypt(data1, key.AesKey[:], key.AesIv[:])
   if err != nil {
      return nil, err
   }
   return append(key.AesIv[:], data1...), nil
}

func (v *La) New(key *a.XmlKey, cipher_data []byte, kid string) error {
   var ecc_pub_key a.WMRM
   x, y, err := ecc_pub_key.Points()
   if err != nil {
      return err
   }
   var el_gamal a.ElGamal
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

func new_envelope(device *c.LocalDevice, kid string) (*Envelope, error) {
   var key a.XmlKey
   err := key.New()
   if err != nil {
      return nil, err
   }
   cipher_data, err := get_cipher_data(&device.CertificateChain, &key)
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
   r, s, err := ecdsa.Sign(a.Fill, device.SigningKey.Key, signed_digest[:])
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

type CertificateChains struct {
   CertificateChain string
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

type Envelope struct {
   XMLName xml.Name `xml:"soap:Envelope"`
   Soap    string   `xml:"xmlns:soap,attr"`
   Body    Body     `xml:"soap:Body"`
}

type EnvelopeResponse struct {
   Body Body
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

type Signature struct {
   SignedInfo     SignedInfo
   SignatureValue string
}

type SignedInfo struct {
   XmlNs     string `xml:"xmlns,attr"`
   Reference Reference
}

type Reference struct {
   Uri         string `xml:"URI,attr"`
   DigestValue string
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

type WrmHeader struct {
   XmlNs   string        `xml:"xmlns,attr"`
   Version string        `xml:"version,attr"`
   Data    WrmHeaderData `xml:"DATA"`
}

type ProtectInfo struct {
   KeyLen string `xml:"KEYLEN"`
   AlgId  string `xml:"ALGID"`
}

type WrmHeaderData struct { // Renamed from DATA
   ProtectInfo ProtectInfo `xml:"PROTECTINFO"`
   Kid         string      `xml:"KID"`
}

type CipherData struct {
   CipherValue string
}

type Algorithm struct {
   Algorithm string `xml:"Algorithm,attr"`
}

type EncryptedData struct {
   XmlNs            string `xml:"xmlns,attr"`
   Type             string `xml:"Type,attr"`
   EncryptionMethod Algorithm
   KeyInfo          KeyInfo
   CipherData       CipherData
}

type KeyInfo struct { // This is the chosen "KeyInfo" type
   XmlNs        string `xml:"xmlns,attr"`
   EncryptedKey EncryptedKey
}

type EncryptedKeyInfo struct { // Renamed from KeyInfo
   XmlNs   string `xml:"xmlns,attr"`
   KeyName string
}

type EncryptedKey struct {
   XmlNs            string `xml:"xmlns,attr"`
   EncryptionMethod Algorithm
   CipherData       CipherData
   KeyInfo          EncryptedKeyInfo
}
