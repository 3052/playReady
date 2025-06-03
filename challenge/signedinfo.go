package challenge

import (
   "encoding/base64"
   "github.com/beevik/etree"
)

func (Challenge) SignedInfo(digest []byte) *etree.Document {
   doc := etree.NewDocument()
   doc.WriteSettings.CanonicalEndTags = true

   doc.CreateChild("SignedInfo", func(e *etree.Element) {
      e.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")
      e.CreateChild("CanonicalizationMethod", func(e *etree.Element) {
         e.CreateAttr("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
      })
      e.CreateChild("SignatureMethod", func(e *etree.Element) {
         e.CreateAttr("Algorithm", "http://schemas.microsoft.com/DRM/2007/03/protocols#ecdsa-sha256")
      })
      e.CreateChild("Reference", func(e *etree.Element) {
         e.CreateAttr("URI", "#SignedData")
         e.CreateChild("DigestMethod", func(e *etree.Element) {
            e.CreateAttr("Algorithm", "http://schemas.microsoft.com/DRM/2007/03/protocols#sha256")
         })
         e.CreateChild("DigestValue", func(e *etree.Element) {
            e.CreateText(base64.StdEncoding.EncodeToString(digest))
         })
      })
   })

   doc.Indent(0)
   return doc
}
