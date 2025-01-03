package playReady

import (
   "bytes"
   "crypto/ecdh"
   "net/http"
   "os"
   "playReady/etree"
)

func DigestValue() (string, error) {
   data, err := os.ReadFile("zgpriv.dat")
   if err != nil {
      return "", err
   }
   encryption_key, err := ecdh.P256().NewPrivateKey(data)
   if err != nil {
      return "", err
   }
   _ = encryption_key
   signing_key, err := ecdh.P256().NewPrivateKey(data)
   if err != nil {
      return "", err
   }
   _ = signing_key
   group_key, err := ecdh.P256().NewPrivateKey(data)
   if err != nil {
      return "", err
   }
   _ = group_key
   data, err = os.ReadFile("bgroupcert.dat")
   if err != nil {
      return "", err
   }
   var certificate_chain bcert_chain
   err = certificate_chain.read(data)
   if err != nil {
      return "", err
   }
   info, err := certificate_chain.Certificates[0].info()
   if err != nil {
      return "", err
   }
   _ = info
   return "", nil
   /*
   new_certificate = Certificate.new_leaf_cert(
      group_key=group_key,
      parent=certificate_chain
      client_id=get_random_bytes(16),
      cert_id=get_random_bytes(16),
      signing_key=signing_key,
      encryption_key=encryption_key,
      security_level=certificate_chain.get_security_level(),
   )
   certificate_chain.prepend(new_certificate)
   device = Device(
      group_certificate=certificate_chain.dumps(),
      encryption_key=encryption_key.dumps(),
      signing_key=signing_key.dumps()
   )
   cdm = Cdm.from_device(device)
   session = self.__sessions.get(session_id)
   session.encryption_key = self.encryption_key
   session.signing_key = self.signing_key
   la_content = self._build_digest_content(
      wmrm_cipher=base64.b64encode(self._get_key_data(session)).decode(),
      cert_cipher=base64.b64encode(self._get_cipher_data(session)).decode()
      content_header=content_header,
      nonce=base64.b64encode(get_random_bytes(16)).decode(),
   )
   la_hash_obj = SHA256.new()
   la_hash_obj.update(la_content.encode())
   la_hash = la_hash_obj.digest()
   return base64.b64encode(la_hash).decode()
   */
}

func license() (*http.Response, error) {
   data := &bytes.Buffer{}
   _, err := license_challenge().WriteTo(data)
   if err != nil {
      return nil, err
   }
   req, err := http.NewRequest(
      "POST", "https://drm-playready-licensing.axtest.net/AcquireLicense", data,
   )
   if err != nil {
      return nil, err
   }
   req.Header.Set("x-axdrm-message", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZXJzaW9uIjoxLCJjb21fa2V5X2lkIjoiYjMzNjRlYjUtNTFmNi00YWUzLThjOTgtMzNjZWQ1ZTMxYzc4IiwibWVzc2FnZSI6eyJ0eXBlIjoiZW50aXRsZW1lbnRfbWVzc2FnZSIsImtleXMiOlt7ImlkIjoiMDg3Mjc4NmUtZjllNy00NjVmLWEzYTItNGU1YjBlZjhmYTQ1IiwiZW5jcnlwdGVkX2tleSI6IlB3NitlRVlOY3ZqWWJmc2gzWDNmbWc9PSJ9LHsiaWQiOiJjMTRmMDcwOS1mMmI5LTQ0MjctOTE2Yi02MWI1MjU4NjUwNmEiLCJlbmNyeXB0ZWRfa2V5IjoiLzErZk5paDM4bXFSdjR5Y1l6bnQvdz09In0seyJpZCI6IjhiMDI5ZTUxLWQ1NmEtNDRiZC05MTBmLWQ0YjVmZDkwZmJhMiIsImVuY3J5cHRlZF9rZXkiOiJrcTBKdVpFanBGTjhzYVRtdDU2ME9nPT0ifSx7ImlkIjoiMmQ2ZTkzODctNjBjYS00MTQ1LWFlYzItYzQwODM3YjRiMDI2IiwiZW5jcnlwdGVkX2tleSI6IlRjUlFlQld4RW9IT0tIcmFkNFNlVlE9PSJ9LHsiaWQiOiJkZTAyZjA3Zi1hMDk4LTRlZTAtYjU1Ni05MDdjMGQxN2ZiYmMiLCJlbmNyeXB0ZWRfa2V5IjoicG9lbmNTN0dnbWVHRmVvSjZQRUFUUT09In0seyJpZCI6IjkxNGU2OWY0LTBhYjMtNDUzNC05ZTlmLTk4NTM2MTVlMjZmNiIsImVuY3J5cHRlZF9rZXkiOiJlaUkvTXNsbHJRNHdDbFJUL0xObUNBPT0ifSx7ImlkIjoiZGE0NDQ1YzItZGI1ZS00OGVmLWIwOTYtM2VmMzQ3YjE2YzdmIiwiZW5jcnlwdGVkX2tleSI6IjJ3K3pkdnFycERWM3hSMGJKeTR1Z3c9PSJ9LHsiaWQiOiIyOWYwNWU4Zi1hMWFlLTQ2ZTQtODBlOS0yMmRjZDQ0Y2Q3YTEiLCJlbmNyeXB0ZWRfa2V5IjoiL3hsU0hweHdxdTNnby9nbHBtU2dhUT09In0seyJpZCI6IjY5ZmU3MDc3LWRhZGQtNGI1NS05NmNkLWMzZWRiMzk5MTg1MyIsImVuY3J5cHRlZF9rZXkiOiJ6dTZpdXpOMnBzaTBaU3hRaUFUa1JRPT0ifV19fQ.BXr93Et1krYMVs-CUnf7F3ywJWFRtxYdkR7Qn4w3-to")
   return http.DefaultClient.Do(req)
}

func license_challenge() *etree.Document {
   doc := etree.NewDocument()
   doc.Element().Create("soap:Envelope", func(e *etree.Element) {
      e.CreateAttr("xmlns:soap", "http://schemas.xmlsoap.org/soap/envelope/")
      e.Create("soap:Body", func(e *etree.Element) {
         e.Create("AcquireLicense", func(e *etree.Element) {
            e.CreateAttr("xmlns", "http://schemas.microsoft.com/DRM/2007/03/protocols")
            e.Create("challenge", func(e *etree.Element) {
               e.Create("Challenge", func(e *etree.Element) {
                  e.CreateAttr("xmlns", "http://schemas.microsoft.com/DRM/2007/03/protocols/messages")
                  e.Create("LA", func(e *etree.Element) {
                     e.CreateAttr("xmlns", "http://schemas.microsoft.com/DRM/2007/03/protocols")
                     e.CreateAttr("Id", "SignedData")
                     e.CreateAttr("xml:space", "preserve")
                     e.Create("Version", func(e *etree.Element) {
                        e.CreateText("1")
                     })
                     e.Create("ContentHeader", func(e *etree.Element) {
                        e.Create("WRMHEADER", func(e *etree.Element) {
                           e.CreateAttr("xmlns", "http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader")
                           e.CreateAttr("version", "4.0.0.0")
                           e.Create("DATA", func(e *etree.Element) {
                              e.Create("PROTECTINFO", func(e *etree.Element) {
                                 e.Create("KEYLEN", func(e *etree.Element) {
                                    e.CreateText("16")
                                 })
                                 e.Create("ALGID", func(e *etree.Element) {
                                    e.CreateText("AESCTR")
                                 })
                              })
                              e.Create("KID", func(e *etree.Element) {
                                 e.CreateText("UZ4Ci2rVvUSRD9S1/ZD7og==")
                              })
                           })
                        })
                     })
                     e.Create("CLIENTINFO", func(e *etree.Element) {
                        e.Create("CLIENTVERSION", func(e *etree.Element) {
                           e.CreateText("10.0.16384.10011")
                        })
                     })
                     e.Create("RevocationLists", func(e *etree.Element) {
                        e.Create("RevListInfo", func(e *etree.Element) {
                           e.Create("ListID", func(e *etree.Element) {
                              e.CreateText("ioydTlK2p0WXkWklprR5Hw==")
                           })
                           e.Create("Version", func(e *etree.Element) {
                              e.CreateText("0")
                           })
                        })
                        e.Create("RevListInfo", func(e *etree.Element) {
                           e.Create("ListID", func(e *etree.Element) {
                              e.CreateText("gC4IKKPHsUCCVhnlttibJw==")
                           })
                           e.Create("Version", func(e *etree.Element) {
                              e.CreateText("0")
                           })
                        })
                        e.Create("RevListInfo", func(e *etree.Element) {
                           e.Create("ListID", func(e *etree.Element) {
                              e.CreateText("Ef/RUojT3U6Ct2jqTCChbA==")
                           })
                           e.Create("Version", func(e *etree.Element) {
                              e.CreateText("0")
                           })
                        })
                        e.Create("RevListInfo", func(e *etree.Element) {
                           e.Create("ListID", func(e *etree.Element) {
                              e.CreateText("BOZ1zT1UnEqfCf5tJOi/kA==")
                           })
                           e.Create("Version", func(e *etree.Element) {
                              e.CreateText("0")
                           })
                        })
                     })
                     e.Create("LicenseNonce", func(e *etree.Element) {
                        e.CreateText("C9kVmWS3zsCJFT6KJbFYCA==")
                     })
                     e.Create("ClientTime", func(e *etree.Element) {
                        e.CreateText("1728844101")
                     })
                     e.Create("EncryptedData", func(e *etree.Element) {
                        e.CreateAttr("xmlns", "http://www.w3.org/2001/04/xmlenc#")
                        e.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Element")
                        e.Create("EncryptionMethod", func(e *etree.Element) {
                           e.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#aes128-cbc")
                        })
                        e.Create("KeyInfo", func(e *etree.Element) {
                           e.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")
                           e.Create("EncryptedKey", func(e *etree.Element) {
                              e.CreateAttr("xmlns", "http://www.w3.org/2001/04/xmlenc#")
                              e.Create("EncryptionMethod", func(e *etree.Element) {
                                 e.CreateAttr("Algorithm", "http://schemas.microsoft.com/DRM/2007/03/protocols#ecc256")
                              })
                              e.Create("KeyInfo", func(e *etree.Element) {
                                 e.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")
                                 e.Create("KeyName", func(e *etree.Element) {
                                    e.CreateText("WMRMServer")
                                 })
                              })
                              e.Create("CipherData", func(e *etree.Element) {
                                 e.Create("CipherValue", func(e *etree.Element) {
                                    e.CreateText("rcPoHgnS6NGMXsU9dRC01AfC8+2J1QrDysOdylZzpIS+wjU1i6WHPG30rOm7K0mreZnIvpKLbXqkxIGI1puMlM6KYa3LezUhneRa9LtAZ+cXbVWzJt2yWJXeGt+93fP2/xYrC5ZHzRokmAKo5OLYAhtRBbX9Wv7uq6jsc2TOHMs=")
                                 })
                              })
                           })
                        })
                        e.Create("CipherData", func(e *etree.Element) {
                           e.Create("CipherValue", func(e *etree.Element) {
                              e.CreateText("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")
                           })
                        })
                     })
                  })
                  e.Create("Signature", func(e *etree.Element) {
                     e.Create("SignedInfo", func(e *etree.Element) {
                        e.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")
                        e.Create("CanonicalizationMethod", func(e *etree.Element) {
                           e.CreateAttr("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
                        })
                        e.Create("SignatureMethod", func(e *etree.Element) {
                           e.CreateAttr("Algorithm", "http://schemas.microsoft.com/DRM/2007/03/protocols#ecdsa-sha256")
                        })
                        e.Create("Reference", func(e *etree.Element) {
                           e.CreateAttr("URI", "#SignedData")
                           e.Create("DigestMethod", func(e *etree.Element) {
                              e.CreateAttr("Algorithm", "http://schemas.microsoft.com/DRM/2007/03/protocols#sha256")
                           })
/////////////////////////////////////////////////////////////////////////////////
                           e.Create("DigestValue", func(e *etree.Element) {
                              e.CreateText("3ZuoaJqKnCfQkMWOvfjDpmnO3gMwFwZf8jOHkcFRvDE=")
                           })
                        })
                     })
                     e.Create("SignatureValue", func(e *etree.Element) {
                        e.CreateText("5Z01ixAuF9AD3PYXiLft5U+r/I19ivCYWo00snefYWktzNbZ9OpSauq3kW04xHgtPeomb3TWN49XtmV1mWMwhg==")
                     })
/////////////////////////////////////////////////////////////////////////////////
                  })
               })
            })
         })
      })
   })
   return doc
}
