package challenge

import (
   "encoding/base64"
   "github.com/beevik/etree"
)

func (Challenge) Root(LA *etree.Document, SignedInfo *etree.Document, Signature []byte, SigningPublicKey []byte) *etree.Document {
   doc := etree.NewDocument()
   doc.WriteSettings.CanonicalEndTags = true

   doc.CreateChild("soap:Envelope", func(e *etree.Element) {
      e.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
      e.CreateAttr("xmlns:xsd", "http://www.w3.org/2001/XMLSchema")
      e.CreateAttr("xmlns:soap", "http://schemas.xmlsoap.org/soap/envelope/")
      e.CreateChild("soap:Body", func(e *etree.Element) {
         e.CreateChild("AcquireLicense", func(e *etree.Element) {
            e.CreateAttr("xmlns", "http://schemas.microsoft.com/DRM/2007/03/protocols")
            e.CreateChild("challenge", func(e *etree.Element) {
               e.CreateChild("Challenge", func(e *etree.Element) {
                  e.CreateAttr("xmlns", "http://schemas.microsoft.com/DRM/2007/03/protocols/messages")
                  e.AddChild(LA.Root())

                  e.CreateChild("Signature", func(e *etree.Element) {
                     e.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")
                     e.AddChild(SignedInfo.Root())
                     e.CreateChild("SignatureValue", func(e *etree.Element) {
                        e.CreateText(base64.StdEncoding.EncodeToString(Signature))
                     })
                     e.CreateChild("KeyInfo", func(e *etree.Element) {
                        e.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")
                        e.CreateChild("KeyValue", func(e *etree.Element) {
                           e.CreateChild("ECCKeyValue", func(e *etree.Element) {
                              e.CreateChild("PublicKey", func(e *etree.Element) {
                                 e.CreateText(base64.StdEncoding.EncodeToString(SigningPublicKey))
                              })
                           })
                        })
                     })
                  })
               })
            })
         })
      })
   })
   doc.Indent(0)
   return doc
}
