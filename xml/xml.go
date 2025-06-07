package xml

import "encoding/xml"

type Envelope struct {
   XMLName xml.Name `xml:"Envelope"`
   Text    string   `xml:",chardata"`
   Xsi     string   `xml:"xsi,attr"`
   Xsd     string   `xml:"xsd,attr"`
   Soap    string   `xml:"soap,attr"`
   Body    struct {
      Text           string `xml:",chardata"`
      AcquireLicense struct {
         Text      string `xml:",chardata"`
         Xmlns     string `xml:"xmlns,attr"`
         Challenge struct {
            Text      string `xml:",chardata"`
            Challenge struct {
               Text  string `xml:",chardata"`
               Xmlns string `xml:"xmlns,attr"`
               LA    struct {
                  Text          string `xml:",chardata"`
                  Xmlns         string `xml:"xmlns,attr"`
                  ID            string `xml:"Id,attr"`
                  Version       string `xml:"Version"`
                  ContentHeader struct {
                     Text      string `xml:",chardata"`
                     WRMHEADER struct {
                        Text    string `xml:",chardata"`
                        Xmlns   string `xml:"xmlns,attr"`
                        Version string `xml:"version,attr"`
                        DATA    struct {
                           Text        string `xml:",chardata"`
                           PROTECTINFO struct {
                              Text   string `xml:",chardata"`
                              KEYLEN string `xml:"KEYLEN"`
                              ALGID  string `xml:"ALGID"`
                           } `xml:"PROTECTINFO"`
                           KID string `xml:"KID"`
                        } `xml:"DATA"`
                     } `xml:"WRMHEADER"`
                  } `xml:"ContentHeader"`
                  EncryptedData struct {
                     Text             string `xml:",chardata"`
                     Xmlns            string `xml:"xmlns,attr"`
                     Type             string `xml:"Type,attr"`
                     EncryptionMethod struct {
                        Text      string `xml:",chardata"`
                        Algorithm string `xml:"Algorithm,attr"`
                     } `xml:"EncryptionMethod"`
                     KeyInfo struct {
                        Text         string `xml:",chardata"`
                        Xmlns        string `xml:"xmlns,attr"`
                        EncryptedKey struct {
                           Text             string `xml:",chardata"`
                           Xmlns            string `xml:"xmlns,attr"`
                           EncryptionMethod struct {
                              Text      string `xml:",chardata"`
                              Algorithm string `xml:"Algorithm,attr"`
                           } `xml:"EncryptionMethod"`
                           KeyInfo struct {
                              Text    string `xml:",chardata"`
                              Xmlns   string `xml:"xmlns,attr"`
                              KeyName string `xml:"KeyName"`
                           } `xml:"KeyInfo"`
                           CipherData struct {
                              Text        string `xml:",chardata"`
                              CipherValue string `xml:"CipherValue"`
                           } `xml:"CipherData"`
                        } `xml:"EncryptedKey"`
                     } `xml:"KeyInfo"`
                     CipherData struct {
                        Text        string `xml:",chardata"`
                        CipherValue string `xml:"CipherValue"`
                     } `xml:"CipherData"`
                  } `xml:"EncryptedData"`
               } `xml:"LA"`
               Signature struct {
                  Text       string `xml:",chardata"`
                  Xmlns      string `xml:"xmlns,attr"`
                  SignedInfo struct {
                     Text                   string `xml:",chardata"`
                     Xmlns                  string `xml:"xmlns,attr"`
                     CanonicalizationMethod struct {
                        Text      string `xml:",chardata"`
                        Algorithm string `xml:"Algorithm,attr"`
                     } `xml:"CanonicalizationMethod"`
                     SignatureMethod struct {
                        Text      string `xml:",chardata"`
                        Algorithm string `xml:"Algorithm,attr"`
                     } `xml:"SignatureMethod"`
                     Reference struct {
                        Text         string `xml:",chardata"`
                        URI          string `xml:"URI,attr"`
                        DigestMethod struct {
                           Text      string `xml:",chardata"`
                           Algorithm string `xml:"Algorithm,attr"`
                        } `xml:"DigestMethod"`
                        DigestValue string `xml:"DigestValue"`
                     } `xml:"Reference"`
                  } `xml:"SignedInfo"`
                  SignatureValue string `xml:"SignatureValue"`
                  KeyInfo        struct {
                     Text     string `xml:",chardata"`
                     Xmlns    string `xml:"xmlns,attr"`
                     KeyValue struct {
                        Text        string `xml:",chardata"`
                        ECCKeyValue struct {
                           Text      string `xml:",chardata"`
                           PublicKey string `xml:"PublicKey"`
                        } `xml:"ECCKeyValue"`
                     } `xml:"KeyValue"`
                  } `xml:"KeyInfo"`
               } `xml:"Signature"`
            } `xml:"Challenge"`
         } `xml:"challenge"`
      } `xml:"AcquireLicense"`
   } `xml:"Body"`
}
