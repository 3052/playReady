package soap

import (
   "41.neocities.org/playReady/a"
   "41.neocities.org/playReady/c"
   "41.neocities.org/playReady/xml"
   "bytes"
   "crypto/ecdsa"
   "crypto/sha256"
   "encoding/base64"
   "errors"
)

func new_la(key *a.XmlKey, cipher_data []byte, kid string) (*xml.La, error) {
   var el_gamal a.ElGamal
   x, y, err := el_gamal.KeyGeneration()
   if err != nil {
      return nil, err
   }
   return &xml.La{
      XmlNs:   "http://schemas.microsoft.com/DRM/2007/03/protocols",
      Id:      "SignedData",
      Version: "1",
      ContentHeader: xml.ContentHeader{
         WrmHeader: xml.WrmHeader{
            XmlNs:   "http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader",
            Version: "4.0.0.0",
            Data: xml.WrmHeaderData{
               ProtectInfo: xml.ProtectInfo{
                  KeyLen: "16",
                  AlgId:  "AESCTR",
               },
               Kid: kid,
            },
         },
      },
      EncryptedData: xml.EncryptedData{
         XmlNs: "http://www.w3.org/2001/04/xmlenc#",
         Type:  "http://www.w3.org/2001/04/xmlenc#Element",
         EncryptionMethod: xml.Algorithm{
            Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
         },
         KeyInfo: xml.KeyInfo{
            XmlNs: "http://www.w3.org/2000/09/xmldsig#",
            EncryptedKey: xml.EncryptedKey{
               XmlNs: "http://www.w3.org/2001/04/xmlenc#",
               EncryptionMethod: xml.Algorithm{
                  Algorithm: "http://schemas.microsoft.com/DRM/2007/03/protocols#ecc256",
               },
               KeyInfo: xml.EncryptedKeyInfo{
                  XmlNs:   "http://www.w3.org/2000/09/xmldsig#",
                  KeyName: "WMRMServer",
               },
               CipherData: xml.CipherData{
                  CipherValue: base64.StdEncoding.EncodeToString(
                     a.ElGamal{}.Encrypt(x, y, &key.PublicKey),
                  ),
               },
            },
         },
         CipherData: xml.CipherData{
            CipherValue: base64.StdEncoding.EncodeToString(cipher_data),
         },
      },
   }, nil
}

func new_envelope(device *c.LocalDevice, kid string) (*xml.Envelope, error) {
   var key a.XmlKey
   err := key.New()
   if err != nil {
      return nil, err
   }
   cipher_data, err := get_cipher_data(&device.CertificateChain, &key)
   if err != nil {
      return nil, err
   }
   la, err := new_la(&key, cipher_data, kid)
   if err != nil {
      return nil, err
   }
   la_data, err := la.Marshal()
   if err != nil {
      return nil, err
   }
   la_digest := sha256.Sum256(la_data)
   signed_info := xml.SignedInfo{
      XmlNs: "http://www.w3.org/2000/09/xmldsig#",
      Reference: xml.Reference{
         Uri:         "#SignedData",
         DigestValue: base64.StdEncoding.EncodeToString(la_digest[:]),
      },
   }
   signed_data, err := signed_info.Marshal()
   if err != nil {
      return nil, err
   }
   signed_digest := sha256.Sum256(signed_data)
   r, s, err := ecdsa.Sign(a.Fill, device.SigningKey.Key, signed_digest[:])
   if err != nil {
      return nil, err
   }
   sign := append(r.Bytes(), s.Bytes()...)
   return &xml.Envelope{
      Soap: "http://schemas.xmlsoap.org/soap/envelope/",
      Body: xml.Body{
         AcquireLicense: &xml.AcquireLicense{
            XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols",
            Challenge: xml.Challenge{
               Challenge: xml.InnerChallenge{
                  XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols/messages",
                  La:    la,
                  Signature: xml.Signature{
                     SignedInfo:     signed_info,
                     SignatureValue: base64.StdEncoding.EncodeToString(sign),
                  },
               },
            },
         },
      },
   }, nil
}

func ParseLicense(device *c.LocalDevice, data []byte) (*a.ContentKey, error) {
   var response xml.EnvelopeResponse
   err := response.Unmarshal(data)
   if err != nil {
      return nil, err
   }
   if fault := response.Body.Fault; fault != nil {
      return nil, errors.New(fault.Fault)
   }
   decoded, err := base64.StdEncoding.DecodeString(response.
      Body.
      AcquireLicenseResponse.
      AcquireLicenseResult.
      Response.
      LicenseResponse.
      Licenses.
      License,
   )
   if err != nil {
      return nil, err
   }
   var license a.LicenseResponse
   err = license.Decode(decoded)
   if err != nil {
      return nil, err
   }
   if !bytes.Equal(license.ECCKeyObject.Value, device.EncryptKey.PublicBytes()) {
      return nil, errors.New("license response is not for this device")
   }
   err = license.ContentKeyObject.Decrypt(device.EncryptKey, license.AuxKeyObject)
   if err != nil {
      return nil, err
   }
   err = license.Verify(license.ContentKeyObject.Integrity.Guid())
   if err != nil {
      return nil, err
   }
   return license.ContentKeyObject, nil
}

func get_cipher_data(chain *c.Chain, key *a.XmlKey) ([]byte, error) {
   value := xml.Data{
      CertificateChains: xml.CertificateChains{
         CertificateChain: base64.StdEncoding.EncodeToString(chain.Encode()),
      },
      Features: xml.Features{
         Feature: xml.Feature{"AESCBC"}, // SCALABLE
      },
   }
   data1, err := value.Marshal()
   if err != nil {
      return nil, err
   }
   data1, err = a.AesCbcPaddingEncrypt(data1, key.AesKey[:], key.AesIv[:])
   if err != nil {
      return nil, err
   }
   return append(key.AesIv[:], data1...), nil
}
