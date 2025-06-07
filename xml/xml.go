package xml

func (e *Envelope) New() {
   *e = Envelope{
      Xsi: "http://www.w3.org/2001/XMLSchema-instance",
      Xsd: "http://www.w3.org/2001/XMLSchema",
      Soap: "http://schemas.xmlsoap.org/soap/envelope/",
      Body: Body{
         AcquireLicense: AcquireLicense{
            XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols",
            Challenge: Challenge{
               Challenge: InnerChallenge{
                  XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols/messages",
                  La: La{
                     XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols",
                     Id: "SignedData",
                     Version: "1",
                     ContentHeader: ContentHeader{
                        WrmHeader: WrmHeader{
                           XmlNs: "http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader",
                           Version: "4.0.0.0",
                           Data: Data{
                              ProtectInfo: ProtectInfo{
                                 AlgId: "AESCTR",
                                 KeyLen: "16",
                              },
                              Kid: "zn6PMa9p48/pbeMb5rdycg==",
                           },
                        },
                     },
                     EncryptedData: EncryptedData{
                        XmlNs: "http://www.w3.org/2001/04/xmlenc#",
                        Type: "http://www.w3.org/2001/04/xmlenc#Element",
                        EncryptionMethod: EncryptionMethod{
                           Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
                        },
                        KeyInfo: KeyInfo{
                           XmlNs: "http://www.w3.org/2000/09/xmldsig#",
                           EncryptedKey: EncryptedKey{
                              XmlNs: "http://www.w3.org/2001/04/xmlenc#",
                              EncryptionMethod: EncryptionMethod{
                                 Algorithm: "http://schemas.microsoft.com/DRM/2007/03/protocols#ecc256",
                              },
                              KeyInfo: InnerKeyInfo{
                                 XmlNs: "http://www.w3.org/2000/09/xmldsig#",
                                 KeyName: "WMRMServer",
                              },
                              CipherData: CipherData{
                                 CipherValue: "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9XEkr5ohMAFWhGEQtZNt8HzA3VerdH2U47YEwu620bxuEVBFFmnGDXepIZctp9Hln1bRncJzL8q4GNoQArjDsSA=",
                              },
                           },
                        },
                        CipherData: CipherData{
                           CipherValue: "Ri26GuT8GpaLTazyDN1tvihzYCrQB7pIhYNKHmdbm",
                        },
                     },
                  },
                  Signature: Signature{
                     XmlNs: "http://www.w3.org/2000/09/xmldsig#",
                     SignedInfo: SignedInfo{
                        XmlNs: "http://www.w3.org/2000/09/xmldsig#",
                        CanonicalizationMethod: CanonicalizationMethod{
                           Algorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
                        },
                        SignatureMethod: SignatureMethod{
                           Algorithm: "http://schemas.microsoft.com/DRM/2007/03/protocols#ecdsa-sha256",
                        },
                        Reference: Reference{
                           Uri: "#SignedData",
                           DigestMethod: DigestMethod{
                              Algorithm: "http://schemas.microsoft.com/DRM/2007/03/protocols#sha256",
                           },
                           DigestValue: "s5fwQ1T0dw9g294q4sAP+bs7mN6sbbz2JZQiRtOQnQQ=",
                        },
                     },
                     SignatureValue: "fdss1cA2jRxNdxuQBxVlv3wpuDbEL4tZv3VNaTkkkhII73fTWNBsdiO2RPKFwUUSxIW34FqbSt0LvtTF+aBU0A==",
                     KeyInfo: SignatureKeyInfo{
                        XmlNs: "http://www.w3.org/2000/09/xmldsig#",
                        KeyValue: KeyValue{
                           ECCKeyValue: ECCKeyValue{
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
}

// Envelope represents the root XML structure.
type Envelope struct {
   Xsi     string   `xml:"xsi,attr"`
   Xsd     string   `xml:"xsd,attr"`
   Soap    string   `xml:"soap,attr"`
   Body    Body 
}

// Body represents the soap body.
type Body struct {
   AcquireLicense AcquireLicense `xml:"AcquireLicense"`
}

// AcquireLicense represents the AcquireLicense element within the Body.
type AcquireLicense struct {
   XmlNs     string    `xml:"xmlns,attr"`
   Challenge Challenge `xml:"Challenge"`
}

// Challenge represents the Challenge element within AcquireLicense.
type Challenge struct {
   Challenge InnerChallenge `xml:"challenge"`
}

// InnerChallenge represents the inner challenge element.
type InnerChallenge struct {
   XmlNs     string    `xml:"xmlns,attr"`
   La        La        `xml:"LA"`
   Signature Signature `xml:"Signature"`
}

type La struct {
   XmlNs         string        `xml:"xmlns,attr"`
   Id            string        `xml:",attr"`
   Version       string        `xml:"Version"`
   ContentHeader ContentHeader `xml:"ContentHeader"`
   EncryptedData EncryptedData `xml:"EncryptedData"`
}

type ContentHeader struct {
   WrmHeader WrmHeader `xml:"WRMHEADER"`
}

type WrmHeader struct {
   XmlNs   string `xml:"xmlns,attr"`
   Version string `xml:"version,attr"`
   Data    Data   `xml:"DATA"`
}

type Data struct {
   ProtectInfo ProtectInfo `xml:"PROTECTINFO"`
   Kid         string      `xml:"KID"`
}

type ProtectInfo struct {
   KeyLen string `xml:"KEYLEN"`
   AlgId  string `xml:"ALGID"`
}

type EncryptedData struct {
   XmlNs            string           `xml:"xmlns,attr"`
   Type             string           `xml:"Type,attr"`
   EncryptionMethod EncryptionMethod `xml:"EncryptionMethod"`
   KeyInfo          KeyInfo          `xml:"KeyInfo"`
   CipherData       CipherData       `xml:"CipherData"`
}

// EncryptionMethod represents the EncryptionMethod element.
type EncryptionMethod struct {
   Algorithm string `xml:"Algorithm,attr"`
}

// KeyInfo represents the KeyInfo element within EncryptedData.
type KeyInfo struct {
   XmlNs        string       `xml:"xmlns,attr"`
   EncryptedKey EncryptedKey `xml:"EncryptedKey"`
}

// EncryptedKey represents the EncryptedKey element within KeyInfo.
type EncryptedKey struct {
   XmlNs            string           `xml:"xmlns,attr"`
   EncryptionMethod EncryptionMethod `xml:"EncryptionMethod"`
   KeyInfo          InnerKeyInfo     `xml:"KeyInfo"`
   CipherData       CipherData       `xml:"CipherData"`
}

// InnerKeyInfo represents the inner KeyInfo element within EncryptedKey.
type InnerKeyInfo struct {
   XmlNs   string `xml:"xmlns,attr"`
   KeyName string `xml:"KeyName"`
}

// CipherData represents the CipherData element.
type CipherData struct {
   CipherValue string `xml:"CipherValue"`
}

// Signature represents the Signature element within InnerChallenge.
type Signature struct {
   XmlNs          string           `xml:"xmlns,attr"`
   SignedInfo     SignedInfo       `xml:"SignedInfo"`
   SignatureValue string           `xml:"SignatureValue"`
   KeyInfo        SignatureKeyInfo `xml:"KeyInfo"`
}

// SignedInfo represents the SignedInfo element within Signature.
type SignedInfo struct {
   XmlNs                  string                 `xml:"xmlns,attr"`
   CanonicalizationMethod CanonicalizationMethod `xml:"CanonicalizationMethod"`
   SignatureMethod        SignatureMethod        `xml:"SignatureMethod"`
   Reference              Reference              `xml:"Reference"`
}

// CanonicalizationMethod represents the CanonicalizationMethod element.
type CanonicalizationMethod struct {
   Algorithm string `xml:"Algorithm,attr"`
}

// SignatureMethod represents the SignatureMethod element.
type SignatureMethod struct {
   Algorithm string `xml:"Algorithm,attr"`
}

// Reference represents the Reference element within SignedInfo.
type Reference struct {
   Uri          string       `xml:"URI,attr"`
   DigestMethod DigestMethod `xml:"DigestMethod"`
   DigestValue  string       `xml:"DigestValue"`
}

// DigestMethod represents the DigestMethod element within Reference.
type DigestMethod struct {
   Algorithm string `xml:"Algorithm,attr"`
}

// SignatureKeyInfo represents the KeyInfo element within Signature.
type SignatureKeyInfo struct {
   XmlNs    string   `xml:"xmlns,attr"`
   KeyValue KeyValue `xml:"KeyValue"`
}

// KeyValue represents the KeyValue element within SignatureKeyInfo.
type KeyValue struct {
   ECCKeyValue ECCKeyValue `xml:"ECCKeyValue"`
}

// ECCKeyValue represents the ECCKeyValue element within KeyValue.
type ECCKeyValue struct {
   PublicKey string `xml:"PublicKey"`
}
