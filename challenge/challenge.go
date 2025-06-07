package challenge

import (
   "41.neocities.org/playReady/crypto"
   "encoding/base64"
)

func (e *Envelope) New() error {
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
                  La: func() La {
                     var value La
                     value.New()
                     return value
                  }(),
                  Signature: Signature{
                     XmlNs: "http://www.w3.org/2000/09/xmldsig#",
                     SignedInfo: SignedInfo{
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
                           DigestValue: "s5fwQ1T0dw9g294q4sAP+bs7mN6sbbz2JZQiRtOQnQQ=",
                        },
                     },
                     SignatureValue: "fdss1cA2jRxNdxuQBxVlv3wpuDbEL4tZv3VNaTkkkhII73fTWNBsdiO2RPKFwUUSxIW34FqbSt0LvtTF+aBU0A==",
                     KeyInfo: SignatureKeyInfo{
                        XmlNs: "http://www.w3.org/2000/09/xmldsig#",
                        KeyValue: KeyValue{
                           EccKeyValue: EccKeyValue{
                              PublicKey: "Ri26GuT8GpaLTazyDN1tvh+uNKqXFRSmPTQFw9HP04O1i7sIwTODQoxYU8ccTIUeE0sFaCHkaP4Kl3q/QxPd4Q==",
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

type AcquireLicense struct {
   Challenge Challenge
   XmlNs     string `xml:"xmlns,attr"`
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

type Data struct {
   Kid         string      `xml:"KID"`
   ProtectInfo ProtectInfo `xml:"PROTECTINFO"`
}

type EccKeyValue struct {
   PublicKey string
}

type EncryptedData struct {
   CipherData       CipherData
   EncryptionMethod AlgorithmType
   KeyInfo          KeyInfo
   Type             string `xml:"Type,attr"`
   XmlNs            string `xml:"xmlns,attr"`
}

type EncryptedKey struct {
   CipherData       CipherData
   EncryptionMethod AlgorithmType
   KeyInfo          InnerKeyInfo
   XmlNs            string `xml:"xmlns,attr"`
}

type Envelope struct {
   Body Body
   Soap string `xml:"xmlns:soap,attr"`
   Xsd  string `xml:"xmlns:xsd,attr"`
   Xsi  string `xml:"xmlns:xsi,attr"`
}

type InnerChallenge struct {
   La        La `xml:"LA"`
   Signature Signature
   XmlNs     string `xml:"xmlns,attr"`
}

type InnerKeyInfo struct {
   KeyName string
   XmlNs   string `xml:"xmlns,attr"`
}

type KeyInfo struct {
   EncryptedKey EncryptedKey
   XmlNs        string `xml:"xmlns,attr"`
}

type KeyValue struct {
   EccKeyValue EccKeyValue `xml:"ECCKeyValue"`
}

type La struct {
   ContentHeader ContentHeader
   EncryptedData EncryptedData
   Id            string `xml:",attr"`
   Version       string
   XmlNs         string `xml:"xmlns,attr"`
}

type ProtectInfo struct {
   AlgId  string `xml:"ALGID"`
   KeyLen string `xml:"KEYLEN"`
}

type Reference struct {
   DigestMethod AlgorithmType
   DigestValue  string
   Uri          string `xml:"URI,attr"`
}

type Signature struct {
   KeyInfo        SignatureKeyInfo
   SignatureValue string
   SignedInfo     SignedInfo
   XmlNs          string `xml:"xmlns,attr"`
}

type SignatureKeyInfo struct {
   KeyValue KeyValue
   XmlNs    string `xml:"xmlns,attr"`
}

type SignedInfo struct {
   CanonicalizationMethod AlgorithmType
   Reference              Reference
   SignatureMethod        AlgorithmType
   XmlNs                  string `xml:"xmlns,attr"`
}

type WrmHeader struct {
   Data    Data   `xml:"DATA"`
   Version string `xml:"version,attr"`
   XmlNs   string `xml:"xmlns,attr"`
}
