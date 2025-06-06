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
      if !bytes.Equal(ParsedLicense.ECCKeyObject.Value, ld.EncryptKey.PublicBytes()) {
         return nil, errors.New("license response is not for this device")
      }
      err = ParsedLicense.ContentKeyObject.Decrypt(ld.EncryptKey, ParsedLicense.AuxKeyObject)
      if err != nil {
         return nil, err
      }
      err = ParsedLicense.Verify(ParsedLicense.ContentKeyObject.Integrity.Bytes())
      if err != nil {
         return nil, err
      }
      Keys = append(
         Keys, KeyData{ParsedLicense.ContentKeyObject.KeyId, ParsedLicense.ContentKeyObject.Key},
      )
   }
   return Keys, nil
}

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
   ld.EncryptKey.LoadBytes(EncryptionKey)
   ld.SigningKey.LoadBytes(SigningKey)
   ld.Version = ClientVersion
   return nil
}
func (ld LocalDevice) GetChallenge(header Header) (string, error) {
   var Challenge Challenge
   return Challenge.Create(ld.CertificateChain, ld.SigningKey, header)
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
