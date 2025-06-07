package playReady

import (
   "41.neocities.org/playReady/crypto"
   "crypto/ecdsa"
   "crypto/sha256"
   "encoding/base64"
   "github.com/beevik/etree"
   "strings"
)

func (Challenge) Root(
   la *etree.Document, SignedInfo *etree.Document,
   Signature, SigningPublicKey []byte,
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

func (Challenge) CipherData(certChain Chain, key crypto.XmlKey) ([]byte, error) {
   doc := etree.NewDocument()
   doc.WriteSettings.CanonicalEndTags = true
   doc.CreateChild("Data", func(e *etree.Element) {
      e.CreateChild("CertificateChains", func(e *etree.Element) {
         e.CreateChild("CertificateChain", func(e *etree.Element) {
            e.CreateText(
               // THIS MIGHT NEED SURROUNDING SPACE
               base64.StdEncoding.EncodeToString(certChain.Encode()),
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
   base, err := doc.WriteToString()
   if err != nil {
      return nil, err
   }
   base = strings.Replace(base, "\n", "", -1)
   var Aes crypto.Aes
   ciphertext, err := Aes.EncryptCBC(key, base)
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
func (Challenge) LicenseAcquisition(
   key crypto.XmlKey, cipher_data []byte, head Header,
) (*etree.Document, error) {
   doc := etree.NewDocument()
   var license_version string
   switch head.WrmHeader.Version {
   case "4.2.0.0":
      license_version = "4"
   case "4.3.0.0":
      license_version = "5"
   default:
      license_version = "1"
   }
   doc.WriteSettings.CanonicalEndTags = true
   var ecc_pub_key crypto.WMRM
   x, y, err := ecc_pub_key.Points()
   if err != nil {
      return nil, err
   }
   // even the order matters
   doc.CreateChild("LA", func(e *etree.Element) {
      e.CreateAttr("xmlns", "http://schemas.microsoft.com/DRM/2007/03/protocols")
      e.CreateAttr("Id", "SignedData")
      e.CreateChild("Version", func(e *etree.Element) {
         e.CreateText(license_version)
      })
      e.CreateChild("ContentHeader", func(e *etree.Element) {
         e.AddChild(head.WrmHeader.Data)
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
                     var (
                        el_gamal crypto.ElGamal
                        encrypted []byte
                     )
                     encrypted, err = el_gamal.Encrypt(x, y, key)
                     e.CreateText(base64.StdEncoding.EncodeToString(encrypted))
                  })
               })
            })
         })
         e.CreateChild("CipherData", func(e *etree.Element) {
            e.CreateChild("CipherValue", func(e *etree.Element) {
               e.CreateText(base64.StdEncoding.EncodeToString(cipher_data))
            })
         })
      })
   })
   if err != nil {
      return nil, err
   }
   doc.Indent(0)
   return doc, nil
}

func (c Challenge) Create(
   certificateChain Chain, signing_key crypto.EcKey, head Header,
) (string, error) {
   var key crypto.XmlKey
   err := key.New()
   if err != nil {
      return "", err
   }
   cipher_data, err := c.CipherData(certificateChain, key)
   if err != nil {
      return "", err
   }
   la, err := c.LicenseAcquisition(key, cipher_data, head)
   if err != nil {
      return "", err
   }
   la_str, err := la.WriteToString()
   if err != nil {
      return "", err
   }
   la_str = strings.Replace(la_str, "\n", "", -1)
   la_digest := sha256.Sum256([]byte(la_str))
   signed_info := c.SignedInfo(la_digest[:])
   signed_str, err := signed_info.WriteToString()
   if err != nil {
      return "", err
   }
   signed_str = strings.Replace(signed_str, "\n", "", -1)
   signed_digest := sha256.Sum256([]byte(signed_str))
   r, s, err := ecdsa.Sign(crypto.Fill, signing_key.Key, signed_digest[:])
   if err != nil {
      return "", err
   }
   sig := append(r.Bytes(), s.Bytes()...)
   challenge := c.Root(la, signed_info, sig, signing_key.PublicBytes())
   base, err := challenge.WriteToString()
   if err != nil {
      return "", err
   }
   challengeStr := `<?xml version="1.0" encoding="utf-8"?>` + base
   return strings.Replace(challengeStr, "\n", "", -1), nil
}

