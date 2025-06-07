package challenge

import (
   "41.neocities.org/playReady/crypto"
   "encoding/base64"
   "encoding/xml"
)

type Data struct {
   XMLName           xml.Name          `xml:"Data"`
   Text              string            `xml:",chardata"`
   CertificateChains CertificateChains `xml:"CertificateChains"`
   Features          Features          `xml:"Features"`
}

type CertificateChains struct {
   Text             string `xml:",chardata"`
   CertificateChain string `xml:"CertificateChain"`
}

type Features struct {
   Text    string  `xml:",chardata"`
   Feature Feature `xml:"Feature"`
}

type Feature struct {
   Text string `xml:",chardata"`
   Name string `xml:"Name,attr"`
}

type Envelope struct {
   XMLName xml.Name `xml:"Envelope"`
   Text    string   `xml:",chardata"`
   Xsi     string   `xml:"xsi,attr"`
   Xsd     string   `xml:"xsd,attr"`
   Soap    string   `xml:"soap,attr"`
   Body    Body     `xml:"Body"`
}

type Body struct {
   Text           string         `xml:",chardata"`
   AcquireLicense AcquireLicense `xml:"AcquireLicense"`
}

type AcquireLicense struct {
   Text      string    `xml:",chardata"`
   XmlNs     string    `xml:"xmlns,attr"`
   Challenge Challenge `xml:"challenge"`
}

type Challenge struct {
   Text      string         `xml:",chardata"`
   Challenge InnerChallenge `xml:"Challenge"`
}

type InnerChallenge struct { // Renamed from Challenge
   Text      string    `xml:",chardata"`
   XmlNs     string    `xml:"xmlns,attr"`
   La        *La       `xml:"LA"`
   Signature Signature `xml:"Signature"`
}

type La struct {
   Text          string        `xml:",chardata"`
   XmlNs         string        `xml:"xmlns,attr"`
   Id            string        `xml:"Id,attr"`
   Version       string        `xml:"Version"`
   ContentHeader ContentHeader `xml:"ContentHeader"`
   EncryptedData EncryptedData `xml:"EncryptedData"`
}

type ContentHeader struct {
   Text      string    `xml:",chardata"`
   WrmHeader WrmHeader `xml:"WRMHEADER"`
}

type WrmHeaderData struct { // Renamed from DATA
   Text        string      `xml:",chardata"`
   ProtectInfo ProtectInfo `xml:"PROTECTINFO"`
   Kid         string      `xml:"KID"`
}

type ProtectInfo struct {
   Text   string `xml:",chardata"`
   KeyLen string `xml:"KEYLEN"`
   AlgId  string `xml:"ALGID"`
}

type EncryptedData struct {
   Text             string     `xml:",chardata"`
   XmlNs            string     `xml:"xmlns,attr"`
   Type             string     `xml:"Type,attr"`
   EncryptionMethod Algorithm  `xml:"EncryptionMethod"`
   KeyInfo          KeyInfo    `xml:"KeyInfo"` // This one remains "KeyInfo"
   CipherData       CipherData `xml:"CipherData"`
}

type KeyInfo struct { // This is the chosen "KeyInfo" type
   Text         string       `xml:",chardata"`
   XmlNs        string       `xml:"xmlns,attr"`
   EncryptedKey EncryptedKey `xml:"EncryptedKey"`
}

type EncryptedKey struct {
   Text             string           `xml:",chardata"`
   XmlNs            string           `xml:"xmlns,attr"`
   EncryptionMethod Algorithm        `xml:"EncryptionMethod"` // Reused type
   KeyInfo          EncryptedKeyInfo `xml:"KeyInfo"`          // Renamed to "EncryptedKeyInfo"
   CipherData       CipherData       `xml:"CipherData"`       // Reused type
}

type CipherData struct {
   Text        string `xml:",chardata"`
   CipherValue string `xml:"CipherValue"`
}

type Signature struct {
   Text           string           `xml:",chardata"`
   XmlNs          string           `xml:"xmlns,attr"`
   SignedInfo     *SignedInfo      `xml:"SignedInfo"`
   SignatureValue string           `xml:"SignatureValue"`
   KeyInfo        SignatureKeyInfo `xml:"KeyInfo"` // Renamed to "SignatureKeyInfo"
}

type SignedInfo struct {
   Text                   string    `xml:",chardata"`
   XmlNs                  string    `xml:"xmlns,attr"`
   CanonicalizationMethod Algorithm `xml:"CanonicalizationMethod"`
   SignatureMethod        Algorithm `xml:"SignatureMethod"`
   Reference              Reference `xml:"Reference"`
}

type Reference struct {
   Text         string    `xml:",chardata"`
   Uri          string    `xml:"URI,attr"`
   DigestMethod Algorithm `xml:"DigestMethod"`
   DigestValue  string    `xml:"DigestValue"`
}

type KeyValue struct {
   Text        string      `xml:",chardata"`
   EccKeyValue EccKeyValue `xml:"ECCKeyValue"`
}

type EccKeyValue struct {
   Text      string `xml:",chardata"`
   PublicKey string `xml:"PublicKey"`
}

type SignatureKeyInfo struct { // Renamed from KeyInfo
   Text     string   `xml:",chardata"`
   XmlNs    string   `xml:"xmlns,attr"`
   KeyValue KeyValue `xml:"KeyValue"`
}

type WrmHeader struct {
   Text    string        `xml:",chardata"`
   XmlNs   string        `xml:"xmlns,attr"`
   Version string        `xml:"version,attr"`
   Data    WrmHeaderData `xml:"DATA"`
}

func (v *La) New(key crypto.XmlKey, cipher_data []byte, kid string) error {
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

type EncryptedKeyInfo struct { // Renamed from KeyInfo
   Text    string `xml:",chardata"`
   XmlNs   string `xml:"xmlns,attr"`
   KeyName string `xml:"KeyName"`
}

func (e *Envelope) New(
   la_data *La, signed_info *SignedInfo, signature, signing_public_key []byte,
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
                  La:    la_data,
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

type Algorithm struct {
   Algorithm string `xml:"Algorithm,attr"`
}
