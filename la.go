package playReady

import (
   "41.neocities.org/playReady/chain"
   "41.neocities.org/playReady/crypto"
   "bytes"
   "encoding/base64"
   "github.com/beevik/etree"
)

func (Challenge) CipherData(
   cert_chain *chain.Chain, key *crypto.XmlKey,
) ([]byte, error) {
   doc := etree.NewDocument()
   doc.WriteSettings.CanonicalEndTags = true
   doc.CreateChild("Data", func(e *etree.Element) {
      e.CreateChild("CertificateChains", func(e *etree.Element) {
         e.CreateChild("CertificateChain", func(e *etree.Element) {
            e.CreateText(
               // THIS MIGHT NEED SURROUNDING SPACE
               base64.StdEncoding.EncodeToString(cert_chain.Encode()),
            )
         })
      })
      e.CreateChild("Features", func(e *etree.Element) {
         e.CreateChild("Feature", func(e *etree.Element) {
            e.CreateAttr("Name", "AESCBC")
         })
      })
   })
   doc.Indent(0)
   base, err := doc.WriteToBytes()
   if err != nil {
      return nil, err
   }
   base = bytes.ReplaceAll(base, []byte{'\n'}, nil)
   var aes crypto.Aes
   ciphertext, err := aes.EncryptCbc(key, base)
   if err != nil {
      return nil, err
   }
   return append(key.AesIv[:], ciphertext...), nil
}

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

type Challenge struct{}

func (Challenge) Root(
   la *etree.Document, signed_info *etree.Document,
   signature, signing_public_key []byte,
) *etree.Document {
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
                  e.AddChild(la.Root())
                  e.CreateChild("Signature", func(e *etree.Element) {
                     e.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")
                     e.AddChild(signed_info.Root())
                     e.CreateChild("SignatureValue", func(e *etree.Element) {
                        e.CreateText(base64.StdEncoding.EncodeToString(signature))
                     })
                     e.CreateChild("KeyInfo", func(e *etree.Element) {
                        e.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")
                        e.CreateChild("KeyValue", func(e *etree.Element) {
                           e.CreateChild("ECCKeyValue", func(e *etree.Element) {
                              e.CreateChild("PublicKey", func(e *etree.Element) {
                                 e.CreateText(base64.StdEncoding.EncodeToString(signing_public_key))
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
