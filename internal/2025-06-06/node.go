package main

import (
   "encoding/xml"
   "os"
)

type node struct {
   XMLName xml.Name
   Attr    []xml.Attr `xml:",attr"`
   Node    []node
   Text    string `xml:",chardata"`
}

func main() {
   value := node{
      XMLName: xml.Name{Local: "LA"},
      Attr: []xml.Attr{
         {
            Name:  xml.Name{Local: "xmlns"},
            Value: "http://schemas.microsoft.com/DRM/2007/03/protocols",
         },
         {
            Name:  xml.Name{Local: "Id"},
            Value: "SignedData",
         },
      },
      Node: []node{
         {
            XMLName: xml.Name{Local: "Version"},
            Text: "1",
         },
      },
   }
   encode := xml.NewEncoder(os.Stdout)
   encode.Indent("", " ")
   err := encode.Encode(value)
   if err != nil {
      panic(err)
   }
}
