package xml

import "encoding/xml"

type InnerChallenge struct { // Renamed from Challenge
   XmlNs     string `xml:"xmlns,attr"`
   La        *La
   Signature Signature
}

func (s *SignedInfo) Marshal() ([]byte, error) {
   return xml.Marshal(s)
}

type SignedInfo struct {
   XmlNs     string `xml:"xmlns,attr"`
   Reference Reference
}

func (l *La) Marshal() ([]byte, error) {
   return xml.Marshal(l)
}

type La struct {
   XMLName       xml.Name `xml:"LA"`
   XmlNs         string   `xml:"xmlns,attr"`
   Id            string   `xml:"Id,attr"`
   Version       string
   ContentHeader ContentHeader
   EncryptedData EncryptedData
}

func (d *Data) Marshal() ([]byte, error) {
   return xml.Marshal(d)
}

type Data struct {
   CertificateChains CertificateChains
   Features          Features
}

func (e *EnvelopeResponse) Unmarshal(data []byte) error {
   return xml.Unmarshal(data, e)
}

type EnvelopeResponse struct {
   Body Body
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

type Envelope struct {
   XMLName xml.Name `xml:"soap:Envelope"`
   Soap    string   `xml:"xmlns:soap,attr"`
   Body    Body     `xml:"soap:Body"`
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

type Signature struct {
   SignedInfo     SignedInfo
   SignatureValue string
}

type Reference struct {
   Uri         string `xml:"URI,attr"`
   DigestValue string
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
