package challenge

import (
   "41.neocities.org/playReady/crypto"
   "encoding/base64"
   "encoding/xml"
)

func (s *SignedInfo) New(digest []byte) {
   *s = SignedInfo{
      XmlNs: "http://www.w3.org/2000/09/xmldsig#",
      CanonicalizationMethod: AlgorithmType{
         Algorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
      },
      SignatureMethod: AlgorithmType{
         Algorithm: "http://schemas.microsoft.com/DRM/2007/03/protocols#ecdsa-sha256",
      },
      Reference: Reference{
         Uri: "#SignedData",
         DigestMethod: AlgorithmType{
            Algorithm: "http://schemas.microsoft.com/DRM/2007/03/protocols#sha256",
         },
         DigestValue: base64.StdEncoding.EncodeToString(digest),
      },
   }
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
            Data: Data{
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
         EncryptionMethod: AlgorithmType{
            Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
         },
         KeyInfo: KeyInfo{
            XmlNs: "http://www.w3.org/2000/09/xmldsig#",
            EncryptedKey: EncryptedKey{
               XmlNs: "http://www.w3.org/2001/04/xmlenc#",
               EncryptionMethod: AlgorithmType{
                  Algorithm: "http://schemas.microsoft.com/DRM/2007/03/protocols#ecc256",
               },
               KeyInfo: InnerKeyInfo{
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
type AlgorithmType struct {
   Algorithm string `xml:"Algorithm,attr"`
}

type Body struct {
   AcquireLicense AcquireLicense
}

type Challenge struct {
   Challenge InnerChallenge `xml:"challenge"`
}

type CipherData struct {
   CipherValue string
}

type ContentHeader struct {
   WrmHeader WrmHeader `xml:"WRMHEADER"`
}

type EccKeyValue struct {
   PublicKey string
}

type KeyValue struct {
   EccKeyValue EccKeyValue `xml:"ECCKeyValue"`
}

type AcquireLicense struct {
   Challenge Challenge
   XmlNs     string `xml:"xmlns,attr"`
}

// KEEP ORDER
type Data struct {
   ProtectInfo ProtectInfo `xml:"PROTECTINFO"`
   Kid         string      `xml:"KID"`
}

// KEEP ORDER
type EncryptedData struct {
   XmlNs            string `xml:"xmlns,attr"`
   Type             string `xml:"Type,attr"`
   EncryptionMethod AlgorithmType
   KeyInfo          KeyInfo
   CipherData       CipherData
}

// KEEP ORDER
type EncryptedKey struct {
   XmlNs            string `xml:"xmlns,attr"`
   EncryptionMethod AlgorithmType
   KeyInfo          InnerKeyInfo
   CipherData       CipherData
}

// KEEP ORDER
type InnerChallenge struct {
   XmlNs     string `xml:"xmlns,attr"`
   La        *La `xml:"LA"`
   Signature Signature
}

type InnerKeyInfo struct {
   XmlNs   string `xml:"xmlns,attr"`
   KeyName string
}

type KeyInfo struct {
   XmlNs        string `xml:"xmlns,attr"`
   EncryptedKey EncryptedKey
}

// KEEP ORDER
type La struct {
   XmlNs         string `xml:"xmlns,attr"`
   Id            string `xml:",attr"`
   Version       string
   ContentHeader ContentHeader
   EncryptedData EncryptedData
}

// KEEP ORDER
type ProtectInfo struct {
   KeyLen string `xml:"KEYLEN"`
   AlgId  string `xml:"ALGID"`
}

// KEEP ORDER
type Reference struct {
   Uri          string `xml:"URI,attr"`
   DigestMethod AlgorithmType
   DigestValue  string
}

// KEEP ORDER
type Signature struct {
   XmlNs          string `xml:"xmlns,attr"`
   SignedInfo     *SignedInfo
   SignatureValue string
   KeyInfo        SignatureKeyInfo
}

type SignatureKeyInfo struct {
   XmlNs    string `xml:"xmlns,attr"`
   KeyValue KeyValue
}

// KEEP ORDER
type SignedInfo struct {
   XmlNs                  string `xml:"xmlns,attr"`
   CanonicalizationMethod AlgorithmType
   SignatureMethod        AlgorithmType
   Reference              Reference
}

// KEEP ORDER
type WrmHeader struct {
   XmlNs   string `xml:"xmlns,attr"`
   Version string `xml:"version,attr"`
   Data    Data   `xml:"DATA"`
}

// KEEP ORDER
type Envelope struct {
   XMLName xml.Name `xml:"soap:Envelope"`
   Xsi     string   `xml:"xmlns:xsi,attr"`
   Xsd     string   `xml:"xmlns:xsd,attr"`
   Soap    string   `xml:"xmlns:soap,attr"`
   Body    Body
}
