package challenge

import (
   "41.neocities.org/playReady/chain"
   "41.neocities.org/playReady/crypto"
   "crypto/ecdsa"
   "crypto/sha256"
   "encoding/base64"
   "encoding/xml"
)

type InnerChallenge struct { // Renamed from Challenge
   XmlNs     string `xml:"xmlns,attr"`
   La        La
   Signature Signature
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

type KeyInfo struct { // This is the chosen "KeyInfo" type
   XmlNs        string `xml:"xmlns,attr"`
   EncryptedKey EncryptedKey
}

type CipherData struct {
   CipherValue string
}

type EncryptedKeyInfo struct { // Renamed from KeyInfo
   XmlNs   string `xml:"xmlns,attr"`
   KeyName string
}

type Signature struct {
   SignedInfo     SignedInfo
   SignatureValue string
}

type La struct {
   XMLName       xml.Name `xml:"LA"`
   XmlNs         string   `xml:"xmlns,attr"`
   Id            string   `xml:"Id,attr"`
   Version       string
   ContentHeader ContentHeader
   EncryptedData EncryptedData
}

type Data struct {
   CertificateChains CertificateChains
}

type EncryptedKey struct {
   XmlNs            string `xml:"xmlns,attr"`
   EncryptionMethod Algorithm
   KeyInfo          EncryptedKeyInfo
   CipherData       CipherData
}

type CertificateChains struct {
   CertificateChain string
}

func (e *Envelope) New(
   certificate_chain *chain.Chain, signing_key crypto.EcKey, kid string,
) error {
   var key crypto.XmlKey
   err := key.New()
   if err != nil {
      return err
   }
   cipher_data, err := get_cipher_data(certificate_chain, &key)
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
   r, s, err := ecdsa.Sign(crypto.Fill, signing_key.Key, signed_digest[:])
   if err != nil {
      return err
   }
   sig := append(r.Bytes(), s.Bytes()...)
   *e = Envelope{
      Soap: "http://schemas.xmlsoap.org/soap/envelope/",
      Body: Body{
         AcquireLicense: AcquireLicense{
            XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols",
            Challenge: Challenge{
               Challenge: InnerChallenge{
                  XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols/messages",
                  La: la_value,
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

func (s *SignedInfo) New(digest []byte) {
   *s = SignedInfo{
      XmlNs: "http://www.w3.org/2000/09/xmldsig#",
      Reference: Reference{
         Uri: "#SignedData",
         DigestValue: base64.StdEncoding.EncodeToString(digest),
      },
   }
}

func get_cipher_data(
   cert_chain *chain.Chain, key *crypto.XmlKey,
) ([]byte, error) {
   data1, err := xml.Marshal(Data{
      CertificateChains: CertificateChains{
         CertificateChain: base64.StdEncoding.EncodeToString(cert_chain.Encode()),
      },
   })
   if err != nil {
      return nil, err
   }
   var aes crypto.Aes
   ciphertext, err := aes.EncryptCbc(key, data1)
   if err != nil {
      return nil, err
   }
   return append(key.AesIv[:], ciphertext...), nil
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

type Reference struct {
   Uri          string `xml:"URI,attr"`
   DigestValue  string
}

type SignedInfo struct {
   XmlNs                  string `xml:"xmlns,attr"`
   Reference              Reference
}

type EncryptedData struct {
   XmlNs            string `xml:"xmlns,attr"`
   Type             string `xml:"Type,attr"`
   EncryptionMethod Algorithm
   KeyInfo          KeyInfo
   CipherData       CipherData
}

type Envelope struct {
   XMLName xml.Name `xml:"soap:Envelope"`
   Soap    string   `xml:"xmlns:soap,attr"`
   Body    Body     `xml:"soap:Body"`
}

type ProtectInfo struct {
   KeyLen string `xml:"KEYLEN"`
   AlgId  string `xml:"ALGID"`
}

type WrmHeader struct {
   XmlNs   string        `xml:"xmlns,attr"`
   Version string        `xml:"version,attr"`
   Data    WrmHeaderData `xml:"DATA"`
}
