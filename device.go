package playReady

import (
   "bytes"
   "encoding/xml"
   "errors"
)

type LocalDevice struct {
   CertificateChain       Chain
   SigningKey, EncryptKey EcKey
   Version                string
}

func (ld *LocalDevice) ParseLicense(response string) (*KeyData, error) {
   var envelope struct {
      Body struct {
         AcquireLicenseResponse struct {
            AcquireLicenseResult struct {
               Response struct {
                  LicenseResponse struct {
                     Licenses struct{ License string }
                  }
               }
            }
         }
      }
   }
   err := xml.Unmarshal([]byte(response), &envelope)
   if err != nil {
      return nil, err
   }
   var license1 LicenseResponse
   err = license1.Parse(
      envelope.
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
   if !bytes.Equal(license1.ECCKeyObject.Value, ld.EncryptKey.PublicBytes()) {
      return nil, errors.New("license response is not for this device")
   }
   err = license1.ContentKeyObject.Decrypt(ld.EncryptKey, license1.AuxKeyObject)
   if err != nil {
      return nil, err
   }
   err = license1.Verify(license1.ContentKeyObject.Integrity.Bytes())
   if err != nil {
      return nil, err
   }
   return &KeyData{
      license1.ContentKeyObject.KeyId, license1.ContentKeyObject.Key,
   }, nil
}

func (ld *LocalDevice) New(CertChain, EncryptionKey, SigningKey []byte, ClientVersion string) error {
   err := ld.CertificateChain.Decode(CertChain)
   if err != nil {
      return err
   }
   ld.EncryptKey.LoadBytes(EncryptionKey)
   ld.SigningKey.LoadBytes(SigningKey)
   ld.Version = ClientVersion
   return nil
}
