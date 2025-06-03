package challenge

import (
   "41.neocities.org/playReady/certificate"
   "41.neocities.org/playReady/crypto"
   "encoding/base64"
   "github.com/beevik/etree"
   "strings"
)

func (Challenge) CipherData(certChain certificate.Chain, key crypto.XmlKey) ([]byte, error) {
   doc := etree.NewDocument()
   doc.WriteSettings.CanonicalEndTags = true

   doc.CreateChild("Data", func(e *etree.Element) {
      e.CreateChild("CertificateChains", func(e *etree.Element) {
         e.CreateChild("CertificateChain", func(e *etree.Element) {
            e.CreateText(" " + base64.StdEncoding.EncodeToString(certChain.Encode()) + " ")
         })
      })
      e.CreateChild("Features", func(e *etree.Element) {
         e.CreateChild("Feature", func(e *etree.Element) {
            e.CreateAttr("Name", "AESCBC")
         })
      })
   })

   doc.Indent(0)

   base, err := doc.WriteToString()
   if err != nil {
      panic(err)
   }

   base = strings.Replace(base, "\n", "", -1)

   var Aes crypto.Aes

   ciphertext, err := Aes.EncryptCBC(key, base)

   return append(key.AesIv[:], ciphertext...), nil
}
