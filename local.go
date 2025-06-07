package playReady

import (
   "41.neocities.org/playReady/chain"
   "41.neocities.org/playReady/crypto"
   "41.neocities.org/playReady/license"
   "bytes"
   "encoding/json"
   "encoding/xml"
   "errors"
   "os"
   "path/filepath"
)

func (ld *LocalDevice) ParseLicense(response string) (*KeyData, error) {
   var envelope struct {
      Body struct {
         AcquireLicenseResponse struct {
            AcquireLicenseResult struct {
               Response struct {
                  LicenseResponse struct {
                     Licenses struct { License string }
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
   var license1 license.LicenseResponse
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
type Config struct {
   Version    string `json:"client_version"`
   CertChain  string `json:"cert_chain"`
   SigningKey string `json:"signing"`
   EncryptKey string `json:"encrypt"`
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

func (ld *LocalDevice) Load(path string) error {
   config, err := os.ReadFile(path + "/pr.json")
   if err != nil {
      return err
   }
   var ParsedConfig Config
   err = json.Unmarshal(config, &ParsedConfig)
   if err != nil {
      return err
   }
   ld.Version = "2.0.1.3"
   if ParsedConfig.Version != "" {
      ld.Version = ParsedConfig.Version
   }
   if ParsedConfig.CertChain == "" {
      return errors.New("missing cert chain")
   }
   err = ld.CertificateChain.LoadFile(filepath.Join(path, ParsedConfig.CertChain))
   if err != nil {
      return err
   }
   if ParsedConfig.SigningKey == "" {
      return errors.New("missing signing key")
   }
   err = ld.SigningKey.LoadFile(filepath.Join(path, ParsedConfig.SigningKey))
   if err != nil {
      return err
   }
   if ParsedConfig.EncryptKey == "" {
      return errors.New("missing encryption key")
   }
   return ld.EncryptKey.LoadFile(filepath.Join(path, ParsedConfig.EncryptKey))
}

type KeyData struct {
   KeyId license.Guid
   Key   license.Guid
}

type LocalDevice struct {
   CertificateChain       chain.Chain
   SigningKey, EncryptKey crypto.EcKey
   Version                string
}
