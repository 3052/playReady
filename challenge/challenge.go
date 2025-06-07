package challenge

import (
   "41.neocities.org/playReady/chain"
   "41.neocities.org/playReady/crypto"
   "crypto/ecdsa"
   "crypto/sha256"
   "encoding/base64"
   "encoding/xml"
)

func New(
   certificate_chain *chain.Chain, signing_key crypto.EcKey, kid string,
) (string, error) {
   var key crypto.XmlKey
   err := key.New()
   if err != nil {
      return "", err
   }
   cipher_data, err := get_cipher_data(certificate_chain, &key)
   if err != nil {
      return "", err
   }
   var la_value La
   err = la_value.New(&key, cipher_data, kid)
   if err != nil {
      return "", err
   }
   la_data, err := xml.Marshal(la_value)
   if err != nil {
      return "", err
   }
   la_digest := sha256.Sum256(la_data)
   var signed_info SignedInfo
   signed_info.New(la_digest[:])
   signed_data, err := xml.Marshal(signed_info)
   if err != nil {
      return "", err
   }
   signed_digest := sha256.Sum256(signed_data)
   r, s, err := ecdsa.Sign(crypto.Fill, signing_key.Key, signed_digest[:])
   if err != nil {
      return "", err
   }
   sig := append(r.Bytes(), s.Bytes()...)
   var root Envelope
   err = root.New(&la_value, &signed_info, sig, signing_key.PublicBytes())
   if err != nil {
      return "", err
   }
   base, err := xml.Marshal(root)
   if err != nil {
      return "", err
   }
   return xml.Header + string(base), nil
}

func (v *La) New(key *crypto.XmlKey, cipher_data []byte, kid string) error {
   var ecc_pub_key crypto.WMRM
   x, y, err := ecc_pub_key.Points()
   if err != nil {
      return err
   }
   var el_gamal crypto.ElGamal
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

func get_cipher_data(
   cert_chain *chain.Chain, key *crypto.XmlKey,
) ([]byte, error) {
   base, err := xml.Marshal(Data{
      CertificateChains: CertificateChains{
         // THIS MIGHT NEED SURROUNDING SPACE
         CertificateChain: base64.StdEncoding.EncodeToString(cert_chain.Encode()),
      },
      Features: Features{
         Feature: Feature{"AESCBC"},
      },
   })
   if err != nil {
      return nil, err
   }
   var aes crypto.Aes
   ciphertext, err := aes.EncryptCbc(key, base)
   if err != nil {
      return nil, err
   }
   return append(key.AesIv[:], ciphertext...), nil
}

type Algorithm struct {
   Algorithm string `xml:"Algorithm,attr"`
}

type Body struct {
   AcquireLicense AcquireLicense
}

type AcquireLicense struct {
   XmlNs     string    `xml:"xmlns,attr"`
   Challenge Challenge `xml:"challenge"`
}

type Challenge struct {
   Challenge InnerChallenge
}

type ContentHeader struct {
   WrmHeader WrmHeader `xml:"WRMHEADER"`
}

type WrmHeaderData struct { // Renamed from DATA
   ProtectInfo ProtectInfo `xml:"PROTECTINFO"`
   Kid         string      `xml:"KID"`
}

type ProtectInfo struct {
   KeyLen string `xml:"KEYLEN"`
   AlgId  string `xml:"ALGID"`
}

type KeyInfo struct { // This is the chosen "KeyInfo" type
   XmlNs        string `xml:"xmlns,attr"`
   EncryptedKey EncryptedKey
}

type CipherData struct {
   CipherValue string
}

type Reference struct {
   Uri          string `xml:"URI,attr"`
   DigestMethod Algorithm
   DigestValue  string
}

type EncryptedKeyInfo struct { // Renamed from KeyInfo
   XmlNs   string `xml:"xmlns,attr"`
   KeyName string
}

type EccKeyValue struct {
   PublicKey string
}

type KeyValue struct {
   EccKeyValue EccKeyValue `xml:"ECCKeyValue"`
}

type SignatureKeyInfo struct { // Renamed from KeyInfo
   XmlNs    string `xml:"xmlns,attr"`
   KeyValue KeyValue
}

type WrmHeader struct {
   XmlNs   string        `xml:"xmlns,attr"`
   Version string        `xml:"version,attr"`
   Data    WrmHeaderData `xml:"DATA"`
}

type EncryptedKey struct {
   XmlNs            string `xml:"xmlns,attr"`
   EncryptionMethod Algorithm
   KeyInfo          EncryptedKeyInfo
   CipherData       CipherData
}

type SignedInfo struct {
   XmlNs                  string `xml:"xmlns,attr"`
   CanonicalizationMethod Algorithm
   SignatureMethod        Algorithm
   Reference              Reference
}

type EncryptedData struct {
   XmlNs            string `xml:"xmlns,attr"`
   Type             string `xml:"Type,attr"`
   EncryptionMethod Algorithm
   KeyInfo          KeyInfo
   CipherData       CipherData
}

type Feature struct {
   Name string `xml:"Name,attr"`
}

type Features struct {
   Feature Feature
}

type Data struct {
   CertificateChains CertificateChains
   Features          Features
}

type CertificateChains struct {
   CertificateChain string
}

func (e *Envelope) New(
   la_value *La, signed_info *SignedInfo, signature, signing_public_key []byte,
) error {
   *e = Envelope{
      Xsi:  "http://www.w3.org/2001/XMLSchema-instance",
      Xsd:  "http://www.w3.org/2001/XMLSchema",
      Soap: "http://schemas.xmlsoap.org/soap/envelope/",
      Body: Body{
         AcquireLicense: AcquireLicense{
            XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols",
            Challenge: Challenge{
               Challenge: InnerChallenge{
                  XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols/messages",
                  La:    la_value,
                  Signature: Signature{
                     XmlNs:          "http://www.w3.org/2000/09/xmldsig#",
                     SignedInfo:     signed_info,
                     SignatureValue: base64.StdEncoding.EncodeToString(signature),
                     KeyInfo: SignatureKeyInfo{
                        XmlNs: "http://www.w3.org/2000/09/xmldsig#",
                        KeyValue: KeyValue{
                           EccKeyValue: EccKeyValue{
                              PublicKey: base64.StdEncoding.EncodeToString(signing_public_key),
                           },
                        },
                     },
                  },
               },
            },
         },
      },
   }
   return nil
}

func (s *SignedInfo) New(digest []byte) {
   *s = SignedInfo{
      XmlNs: "http://www.w3.org/2000/09/xmldsig#",
      CanonicalizationMethod: Algorithm{
         Algorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
      },
      SignatureMethod: Algorithm{
         Algorithm: "http://schemas.microsoft.com/DRM/2007/03/protocols#ecdsa-sha256",
      },
      Reference: Reference{
         Uri: "#SignedData",
         DigestMethod: Algorithm{
            Algorithm: "http://schemas.microsoft.com/DRM/2007/03/protocols#sha256",
         },
         DigestValue: base64.StdEncoding.EncodeToString(digest),
      },
   }
}

type Envelope struct {
   XMLName xml.Name `xml:"soap:Envelope"`
   Xsi     string   `xml:"xmlns:xsi,attr"`
   Xsd     string   `xml:"xmlns:xsd,attr"`
   Soap    string   `xml:"xmlns:soap,attr"`
   Body    Body     `xml:"soap:Body"`
}

type La struct {
   XMLName       xml.Name `xml:"LA"`
   XmlNs         string   `xml:"xmlns,attr"`
   Id            string   `xml:"Id,attr"`
   Version       string
   ContentHeader ContentHeader
   EncryptedData EncryptedData
}

type InnerChallenge struct { // Renamed from Challenge
   XmlNs     string `xml:"xmlns,attr"`
   La        *La
   Signature Signature
}

type Signature struct {
   XmlNs          string `xml:"xmlns,attr"`
   SignedInfo     *SignedInfo
   SignatureValue string
   KeyInfo        SignatureKeyInfo
}
