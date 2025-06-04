package challenge

import (
   "41.neocities.org/playReady/certificate"
   "41.neocities.org/playReady/crypto"
   "41.neocities.org/playReady/header"
   "crypto/ecdsa"
   "crypto/rand"
   "crypto/sha256"
   "encoding/base64"
   "fmt"
   "github.com/beevik/etree"
   "strings"
)

type Challenge struct{}

func (c *Challenge) Create(certificateChain certificate.Chain, signingKey crypto.EcKey, header header.Header) (string, error) {
   var key crypto.XmlKey
   err := key.New()
   if err != nil {
      panic(err)
   }
   cipherData, err := c.CipherData(certificateChain, key)
   LA, err := c.LicenseAcquisition(key, cipherData, header)
   LAStr, err := LA.WriteToString()
   if err != nil {
      panic(err)
   }
   LAStr = strings.Replace(LAStr, "\n", "", -1)
   LADigest := sha256.Sum256([]byte(LAStr))
   SignedInfo := c.SignedInfo(LADigest[:])
   SignedStr, err := SignedInfo.WriteToString()
   if err != nil {
      panic(err)
   }
   SignedStr = strings.Replace(SignedStr, "\n", "", -1)
   SignedDigest := sha256.Sum256([]byte(SignedStr))
   r, s, err := ecdsa.Sign(rand.Reader, signingKey.Key, SignedDigest[:])
   if err != nil {
      fmt.Println("failed to sign")
   }
   sig := r.Bytes()
   sig = append(sig, s.Bytes()...)
   challenge := c.Root(LA, SignedInfo, sig, signingKey.PublicBytes())
   base, err := challenge.WriteToString()
   if err != nil {
      panic(err)
   }
   xmlHeader := `<?xml version="1.0" encoding="utf-8"?>`
   challengeStr := xmlHeader + base
   challengeStr = strings.Replace(challengeStr, "\n", "", -1)
   return challengeStr, nil
}
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
