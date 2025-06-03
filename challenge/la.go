package challenge

import (
   "41.neocities.org/playReady/crypto"
   "41.neocities.org/playReady/header"
   "encoding/base64"
   "github.com/beevik/etree"
   "math/rand"
   "strconv"
   "time"
)

func (Challenge) LicenseAcquisition(key crypto.XmlKey, cipherData []byte, header header.Header) (*etree.Document, error) {
   doc := etree.NewDocument()
   doc.WriteSettings.CanonicalEndTags = true

   LicenseNonce := make([]byte, 16)
   _, err := rand.Read(LicenseNonce)

   if err != nil {
      panic(err)
   }

   var WMRMEccPubKey crypto.WMRM

   x, y, err := WMRMEccPubKey.Points()

   if err != nil {
      panic(err)
   }

   var LicenseVersion string

   switch header.WrmHeader.Version {
   case "4.2.0.0":
      LicenseVersion = "4"
   case "4.3.0.0":
      LicenseVersion = "5"
   default:
      LicenseVersion = "1"
   }

   var elgamal crypto.ElGamal

   doc.WriteSettings.CanonicalEndTags = true

   doc.CreateChild("LA", func(e *etree.Element) {
      e.CreateAttr("xmlns", "http://schemas.microsoft.com/DRM/2007/03/protocols")
      e.CreateAttr("Id", "SignedData")
      e.CreateAttr("xml:space", "preserve")
      e.CreateChild("Version", func(e *etree.Element) {
         e.CreateText(LicenseVersion)
      })
      e.CreateChild("ContentHeader", func(e *etree.Element) {
         e.AddChild(header.WrmHeader.Data)
      })
      e.CreateChild("CLIENTINFO", func(e *etree.Element) {
         e.CreateChild("CLIENTVERSION", func(e *etree.Element) {
            e.CreateText("4.0.1.2")
         })
      })

      e.CreateChild("LicenseNonce", func(e *etree.Element) {
         e.CreateText(base64.StdEncoding.EncodeToString(LicenseNonce))
      })
      e.CreateChild("ClientTime", func(e *etree.Element) {
         e.CreateText(strconv.FormatInt(time.Now().Unix(), 10))
      })
      e.CreateChild("EncryptedData", func(e *etree.Element) {
         e.CreateAttr("xmlns", "http://www.w3.org/2001/04/xmlenc#")
         e.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Element")
         e.CreateChild("EncryptionMethod", func(e *etree.Element) {
            e.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#aes128-cbc")
         })
         e.CreateChild("KeyInfo", func(e *etree.Element) {
            e.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")
            e.CreateChild("EncryptedKey", func(e *etree.Element) {
               e.CreateAttr("xmlns", "http://www.w3.org/2001/04/xmlenc#")
               e.CreateChild("EncryptionMethod", func(e *etree.Element) {
                  e.CreateAttr("Algorithm", "http://schemas.microsoft.com/DRM/2007/03/protocols#ecc256")
               })
               e.CreateChild("KeyInfo", func(e *etree.Element) {
                  e.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")
                  e.CreateChild("KeyName", func(e *etree.Element) {
                     e.CreateText("WMRMServer")
                  })
               })
               e.CreateChild("CipherData", func(e *etree.Element) {
                  e.CreateChild("CipherValue", func(e *etree.Element) {
                     encrypted := elgamal.Encrypt(x, y, key)
                     e.CreateText(base64.StdEncoding.EncodeToString(encrypted))
                  })
               })
            })
         })
         e.CreateChild("CipherData", func(e *etree.Element) {
            e.CreateChild("CipherValue", func(e *etree.Element) {
               e.CreateText(base64.StdEncoding.EncodeToString(cipherData))
            })
         })
      })
   })

   doc.Indent(0)

   return doc, nil
}
