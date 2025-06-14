package soap

import (
   "41.neocities.org/playReady/a"
   "41.neocities.org/playReady/c"
   "bytes"
   "encoding/base64"
   "encoding/hex"
   "encoding/xml"
   "io"
   "log"
   "net/http"
   "os"
   "testing"
)

func TestRakuten(t *testing.T) {
   var device c.LocalDevice
   data, err := os.ReadFile(SL2000.dir + "chain.txt")
   if err != nil {
      t.Fatal(err)
   }
   err = device.CertificateChain.Decode(data)
   if err != nil {
      t.Fatal(err)
   }
   data, err = os.ReadFile(SL2000.dir + "signing_key.txt")
   if err != nil {
      t.Fatal(err)
   }
   device.SigningKey.LoadBytes(data)
   data, err = os.ReadFile(SL2000.dir + "encrypt_key.txt")
   if err != nil {
      t.Fatal(err)
   }
   device.EncryptKey.LoadBytes(data)
   envelope1, err := new_envelope(&device, rakuten.kid_pr)
   if err != nil {
      t.Fatal(err)
   }
   data, err = xml.Marshal(envelope1)
   if err != nil {
      t.Fatal(err)
   }
   resp, err := http.Post(rakuten.url, "", bytes.NewReader(data))
   if err != nil {
      t.Fatal(err)
   }
   defer resp.Body.Close()
   data, err = io.ReadAll(resp.Body)
   if err != nil {
      t.Fatal(err)
   }
   key, err := ParseLicense(&device, data)
   if err != nil {
      t.Fatal(err)
   }
   if hex.EncodeToString(key.KeyId.Uuid()) != rakuten.kid_wv {
      t.Fatal(".KeyId")
   }
   if hex.EncodeToString(key.Key[:]) != rakuten.key {
      t.Fatal(".Key")
   }
}
var rakuten = struct {
   content string
   key     string
   url     string
   kid_wv  string
   kid_pr  string
}{
   url:     "https://prod-playready.rakuten.tv/v1/licensing/pr?uuid=478731cf-95ff-4412-95f8-2ca967c8b93c",
   content: "rakuten.tv/cz?content_type=movies&content_id=transvulcania-the-people-s-run",
   key:     "ab82952e8b567a2359393201e4dde4b4",
   kid_wv:  "318f7ece69afcfe3e96de31be6b77272",
   kid_pr:  "zn6PMa9p48/pbeMb5rdycg==",
}

var SL2000 = struct{
   dir string
   g1  string
   z1  string
}{
   dir: "../ignore/",
   g1:  "g1",
   z1:  "z1",
}

func TestChain(t *testing.T) {
   data, err := os.ReadFile(SL2000.dir + SL2000.g1)
   if err != nil {
      t.Fatal(err)
   }
   var chain c.Chain
   err = chain.Decode(data)
   if err != nil {
      t.Fatal(err)
   }
   data, err = os.ReadFile(SL2000.dir + SL2000.z1)
   if err != nil {
      t.Fatal(err)
   }
   var z1 a.EcKey
   z1.LoadBytes(data)
   // they downgrade certs from the cert digest (hash of the signing key)
   var signing_key a.EcKey
   err = signing_key.New()
   if err != nil {
      t.Fatal(err)
   }
   var encrypt_key a.EcKey
   err = encrypt_key.New()
   if err != nil {
      t.Fatal(err)
   }
   err = chain.CreateLeaf(z1, signing_key, encrypt_key)
   if err != nil {
      t.Fatal(err)
   }
   err = write_file(SL2000.dir+"chain.txt", chain.Encode())
   if err != nil {
      t.Fatal(err)
   }
   err = write_file(SL2000.dir+"signing_key.txt", signing_key.Private())
   if err != nil {
      t.Fatal(err)
   }
   err = write_file(SL2000.dir+"encrypt_key.txt", encrypt_key.Private())
   if err != nil {
      t.Fatal(err)
   }
}

func write_file(name string, data []byte) error {
   log.Println("WriteFile", name)
   return os.WriteFile(name, data, os.ModePerm)
}

func TestScalable(t *testing.T) {
   var device c.LocalDevice
   data, err := os.ReadFile(SL2000.dir + "chain.txt")
   if err != nil {
      t.Fatal(err)
   }
   err = device.CertificateChain.Decode(data)
   if err != nil {
      t.Fatal(err)
   }
   data, err = os.ReadFile(SL2000.dir + "signing_key.txt")
   if err != nil {
      t.Fatal(err)
   }
   device.SigningKey.LoadBytes(data)
   data, err = os.ReadFile(SL2000.dir + "encrypt_key.txt")
   if err != nil {
      t.Fatal(err)
   }
   device.EncryptKey.LoadBytes(data)
   key_id := [16]byte{1}
   envelope1, err := new_envelope(
      &device, base64.StdEncoding.EncodeToString(key_id[:]),
   )
   if err != nil {
      t.Fatal(err)
   }
   data, err = xml.Marshal(envelope1)
   if err != nil {
      t.Fatal(err)
   }
   resp, err := http.Post(
      "https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=(persist:false,ck:AAAAAAAAAAAAAAAAAAAAAA==,ckt:aescbc)",
      "text/xml", bytes.NewReader(data),
   )
   if err != nil {
      t.Fatal(err)
   }
   defer resp.Body.Close()
   data, err = io.ReadAll(resp.Body)
   if err != nil {
      t.Fatal(err)
   }
   key, err := ParseLicense(&device, data)
   if err != nil {
      t.Fatal(err)
   }
   if !bytes.Equal(key.KeyId.Guid(), key_id[:]) {
      t.Fatal(".KeyId")
   }
   var zero [16]byte
   if !bytes.Equal(key.Key[:], zero[:]) {
      t.Fatal(".Key")
   }
}
