package playReady

import (
   "41.neocities.org/playReady/crypto"
   "41.neocities.org/playReady/license"
   "bytes"
   "encoding/json"
   "errors"
   "github.com/beevik/etree"
   "os"
   "path/filepath"
   "strings"
)

type Config struct {
   Version    string `json:"client_version"`
   CertChain  string `json:"cert_chain"`
   SigningKey string `json:"signing"`
   EncryptKey string `json:"encrypt"`
}

type LocalDevice struct {
   CertificateChain       Chain
   SigningKey, EncryptKey crypto.EcKey
   Version                string
}

func (ld *LocalDevice) New(CertChain, EncryptionKey, SigningKey []byte, ClientVersion string) error {
   err := ld.CertificateChain.Decode(CertChain)

   if err != nil {
      return err
   }

   err = ld.EncryptKey.LoadBytes(EncryptionKey)

   if err != nil {
      return err
   }

   err = ld.SigningKey.LoadBytes(SigningKey)

   if err != nil {
      return err
   }

   ld.Version = ClientVersion

   return nil
}

func (ld *LocalDevice) Load(path string) error {
   config, err := os.ReadFile(path + "/pr.json")

   if err != nil {
      return err
   }

   var ParsedConfig Config

   _ = json.Unmarshal(config, &ParsedConfig)

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

   err = ld.EncryptKey.LoadFile(filepath.Join(path, ParsedConfig.EncryptKey))

   if err != nil {
      return err
   }

   return nil
}

func (ld LocalDevice) GetChallenge(header Header) (string, error) {
   var Challenge Challenge
   return Challenge.Create(ld.CertificateChain, ld.SigningKey, header)
}

type KeyData struct {
   KeyId license.Guid
   Key   license.Guid
}

func (ld LocalDevice) ParseLicense(response string) ([]KeyData, error) {
   License := etree.NewDocument()
   if err := License.ReadFromString(response); err != nil {
      return nil, err
   }

   var Keys []KeyData

   for _, e := range License.FindElements("./soap:Envelope/soap:Body/AcquireLicenseResponse/AcquireLicenseResult/Response/LicenseResponse/Licenses/*") {
      var ParsedLicense license.LicenseResponse
      err := ParsedLicense.Parse(strings.TrimSpace(e.Text()))

      if err != nil {
         return nil, err
      }

      if bytes.Equal(ParsedLicense.ECCKeyObject.Value, ld.EncryptKey.PublicBytes()) == false {
         return nil, errors.New("license response is not for this device")
      }

      err = ParsedLicense.ContentKeyObject.Decrypt(ld.EncryptKey, ParsedLicense.AuxKeyObject)

      if err != nil {
         return Keys, err
      }

      if !ParsedLicense.Verify(ParsedLicense.ContentKeyObject.Integrity.Bytes()) {
         return nil, errors.New("failed to decrypt the keys")
      }

      Keys = append(Keys, KeyData{ParsedLicense.ContentKeyObject.KeyId, ParsedLicense.ContentKeyObject.Key})
   }

   return Keys, nil
}
