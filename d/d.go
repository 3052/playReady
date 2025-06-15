package d

import (
   "41.neocities.org/playReady/a"
   "41.neocities.org/playReady/cert"
   "41.neocities.org/playReady/elGamal"
   "41.neocities.org/playReady/xml"
   "bytes"
   "crypto/ecdsa"
   "crypto/sha256"
   "encoding/base64"
   "errors"
)

func newLa(m *ecdsa.PublicKey, cipherData []byte, kid string) xml.La {
   return xml.La{
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
                     elGamal.Encrypt(m, elGamal.KeyGeneration()),
                  ),
               },
            },
         },
         CipherData: xml.CipherData{
            CipherValue: base64.StdEncoding.EncodeToString(cipherData),
         },
      },
   }
}

// NewEnvelope creates a new SOAP envelope for a license acquisition challenge.
// This function remains public because it's likely intended for external use.
func NewEnvelope(device *cert.LocalDevice, kid string) (*xml.Envelope, error) {
   var key a.XmlKey
   key.New()
   cipherData, err := getCipherData(&device.CertificateChain, &key)
   if err != nil {
      return nil, err
   }
   la := newLa(&key.PublicKey, cipherData, kid)
   laData, err := la.Marshal()
   if err != nil {
      return nil, err
   }
   laDigest := sha256.Sum256(laData)
   signedInfo := xml.SignedInfo{
      XmlNs: "http://www.w3.org/2000/09/xmldsig#",
      Reference: xml.Reference{
         Uri:         "#SignedData",
         DigestValue: base64.StdEncoding.EncodeToString(laDigest[:]),
      },
   }
   signedData, err := signedInfo.Marshal()
   if err != nil {
      return nil, err
   }
   signedDigest := sha256.Sum256(signedData)
   r, s, err := ecdsa.Sign(a.Fill('C'), device.SigningKey[0], signedDigest[:])
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
                     SignedInfo:     signedInfo,
                     SignatureValue: base64.StdEncoding.EncodeToString(sign),
                  },
               },
            },
         },
      },
   }, nil
}

// ParseLicense parses a SOAP response containing a PlayReady license.
// This function remains public because it's likely intended for external use.
func ParseLicense(device *cert.LocalDevice, data []byte) (*a.ContentKey, error) {
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
   if !bytes.Equal(license.EccKeyObject.Value, device.EncryptKey.PublicBytes()) {
      return nil, errors.New("license response is not for this device")
   }
   err = license.ContentKeyObject.Decrypt(
      device.EncryptKey[0], license.AuxKeyObject,
   )
   if err != nil {
      return nil, err
   }
   err = license.Verify(license.ContentKeyObject.Integrity.Guid())
   if err != nil {
      return nil, err
   }
   return license.ContentKeyObject, nil
}

func getCipherData(chain *cert.Chain, key *a.XmlKey) ([]byte, error) {
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
   data1, err = a.AesCbcPaddingEncrypt(data1, key.AesKey(), key.AesIv())
   if err != nil {
      return nil, err
   }
   return append(key.AesIv(), data1...), nil
}
