package xml

import "encoding/xml"

// Envelope represents the root XML structure.
type Envelope struct {
   XMLName xml.Name `xml:"Envelope"`
   Text    string   `xml:",chardata"`
   Xsi     string   `xml:"xsi,attr"`
   Xsd     string   `xml:"xsd,attr"`
   Soap    string   `xml:"soap,attr"`
   Body    Body     `xml:"Body"`
}

// Body represents the soap body.
type Body struct {
   Text           string         `xml:",chardata"`
   AcquireLicense AcquireLicense `xml:"AcquireLicense"`
}

// AcquireLicense represents the AcquireLicense element within the Body.
type AcquireLicense struct {
   Text      string    `xml:",chardata"`
   Xmlns     string    `xml:"xmlns,attr"`
   Challenge Challenge `xml:"Challenge"`
}

// Challenge represents the Challenge element within AcquireLicense.
type Challenge struct {
   Text      string `xml:",chardata"`
   Challenge InnerChallenge `xml:"challenge"`
}

// InnerChallenge represents the inner challenge element.
type InnerChallenge struct {
   Text  string `xml:",chardata"`
   Xmlns string `xml:"xmlns,attr"`
   LA    LA     `xml:"LA"`
   Signature Signature `xml:"Signature"`
}

// LA represents the LA element within the InnerChallenge.
type LA struct {
   Text          string        `xml:",chardata"`
   Xmlns         string        `xml:"xmlns,attr"`
   ID            string        `xml:"Id,attr"`
   Version       string        `xml:"Version"`
   ContentHeader ContentHeader `xml:"ContentHeader"`
   EncryptedData EncryptedData `xml:"EncryptedData"`
}

// ContentHeader represents the ContentHeader element within LA.
type ContentHeader struct {
   Text    string    `xml:",chardata"`
   WRMHEADER WRMHEADER `xml:"WRMHEADER"`
}

// WRMHEADER represents the WRMHEADER element within ContentHeader.
type WRMHEADER struct {
   Text    string `xml:",chardata"`
   Xmlns   string `xml:"xmlns,attr"`
   Version string `xml:"version,attr"`
   DATA    DATA   `xml:"DATA"`
}

// DATA represents the DATA element within WRMHEADER.
type DATA struct {
   Text        string      `xml:",chardata"`
   PROTECTINFO PROTECTINFO `xml:"PROTECTINFO"`
   KID         string      `xml:"KID"`
}

// PROTECTINFO represents the PROTECTINFO element within DATA.
type PROTECTINFO struct {
   Text   string `xml:",chardata"`
   KEYLEN string `xml:"KEYLEN"`
   ALGID  string `xml:"ALGID"`
}

// EncryptedData represents the EncryptedData element within LA.
type EncryptedData struct {
   Text             string           `xml:",chardata"`
   Xmlns            string           `xml:"xmlns,attr"`
   Type             string           `xml:"Type,attr"`
   EncryptionMethod EncryptionMethod `xml:"EncryptionMethod"`
   KeyInfo          KeyInfo          `xml:"KeyInfo"`
   CipherData       CipherData       `xml:"CipherData"`
}

// EncryptionMethod represents the EncryptionMethod element.
type EncryptionMethod struct {
   Text      string `xml:",chardata"`
   Algorithm string `xml:"Algorithm,attr"`
}

// KeyInfo represents the KeyInfo element within EncryptedData.
type KeyInfo struct {
   Text         string       `xml:",chardata"`
   Xmlns        string       `xml:"xmlns,attr"`
   EncryptedKey EncryptedKey `xml:"EncryptedKey"`
}

// EncryptedKey represents the EncryptedKey element within KeyInfo.
type EncryptedKey struct {
   Text             string           `xml:",chardata"`
   Xmlns            string           `xml:"xmlns,attr"`
   EncryptionMethod EncryptionMethod `xml:"EncryptionMethod"`
   KeyInfo          InnerKeyInfo     `xml:"KeyInfo"`
   CipherData       CipherData       `xml:"CipherData"`
}

// InnerKeyInfo represents the inner KeyInfo element within EncryptedKey.
type InnerKeyInfo struct {
   Text    string `xml:",chardata"`
   Xmlns   string `xml:"xmlns,attr"`
   KeyName string `xml:"KeyName"`
}

// CipherData represents the CipherData element.
type CipherData struct {
   Text        string `xml:",chardata"`
   CipherValue string `xml:"CipherValue"`
}

// Signature represents the Signature element within InnerChallenge.
type Signature struct {
   Text         string     `xml:",chardata"`
   Xmlns        string     `xml:"xmlns,attr"`
   SignedInfo   SignedInfo `xml:"SignedInfo"`
   SignatureValue string     `xml:"SignatureValue"`
   KeyInfo      SignatureKeyInfo `xml:"KeyInfo"`
}

// SignedInfo represents the SignedInfo element within Signature.
type SignedInfo struct {
   Text                   string                 `xml:",chardata"`
   Xmlns                  string                 `xml:"xmlns,attr"`
   CanonicalizationMethod CanonicalizationMethod `xml:"CanonicalizationMethod"`
   SignatureMethod        SignatureMethod        `xml:"SignatureMethod"`
   Reference              Reference              `xml:"Reference"`
}

// CanonicalizationMethod represents the CanonicalizationMethod element.
type CanonicalizationMethod struct {
   Text      string `xml:",chardata"`
   Algorithm string `xml:"Algorithm,attr"`
}

// SignatureMethod represents the SignatureMethod element.
type SignatureMethod struct {
   Text      string `xml:",chardata"`
   Algorithm string `xml:"Algorithm,attr"`
}

// Reference represents the Reference element within SignedInfo.
type Reference struct {
   Text        string       `xml:",chardata"`
   URI         string       `xml:"URI,attr"`
   DigestMethod DigestMethod `xml:"DigestMethod"`
   DigestValue string       `xml:"DigestValue"`
}

// DigestMethod represents the DigestMethod element within Reference.
type DigestMethod struct {
   Text      string `xml:",chardata"`
   Algorithm string `xml:"Algorithm,attr"`
}

// SignatureKeyInfo represents the KeyInfo element within Signature.
type SignatureKeyInfo struct {
   Text    string   `xml:",chardata"`
   Xmlns   string   `xml:"xmlns,attr"`
   KeyValue KeyValue `xml:"KeyValue"`
}

// KeyValue represents the KeyValue element within SignatureKeyInfo.
type KeyValue struct {
   Text        string      `xml:",chardata"`
   ECCKeyValue ECCKeyValue `xml:"ECCKeyValue"`
}

// ECCKeyValue represents the ECCKeyValue element within KeyValue.
type ECCKeyValue struct {
   Text      string `xml:",chardata"`
   PublicKey string `xml:"PublicKey"`
}
