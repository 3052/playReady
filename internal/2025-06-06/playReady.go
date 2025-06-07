package main

import (
   "encoding/xml"
   "os"
)

func main() {
   value := hello{
      XMLName: xml.Name{Local: "alfa"},
      Attr: []xml.Attr{
         {
            Name: xml.Name{Local: "zero"},
            Value: "true",
         },
         {
            Name: xml.Name{Local: "one"},
            Value: "true",
         },
      },
      Hello: []hello{
         {
            XMLName: xml.Name{Local: "bravo"},
            Attr: []xml.Attr{
               {
                  Name: xml.Name{Local: "zero"},
                  Value: "true",
               },
            },
            Text: "text",
         },
      },
   }
   encode := xml.NewEncoder(os.Stdout)
   encode.Indent("", "\t")
   err := encode.Encode(value)
   if err != nil {
      panic(err)
   }
}

type hello struct {
   Attr []xml.Attr `xml:",attr"`
   Hello []hello
   Text string `xml:",chardata"`
   XMLName xml.Name
}

type LA struct {
   XMLName       xml.Name `xml:"LA"`
   Text          string   `xml:",chardata"`
   Xmlns         string   `xml:"xmlns,attr"`
   ID            string   `xml:"Id,attr"`
   Version       string   `xml:"Version"`
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
            KID      string `xml:"KID"`
            CHECKSUM string `xml:"CHECKSUM"`
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
}
