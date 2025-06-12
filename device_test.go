package playReady

import (
   "bytes"
   "encoding/base64"
   "encoding/hex"
   "encoding/xml"
   "io"
   "net/http"
   "os"
   "testing"
)

func TestScalable(t *testing.T) {
   var device LocalDevice
   data, err := os.ReadFile(tester.dir + "chain.txt")
   if err != nil {
      t.Fatal(err)
   }
   err = device.CertificateChain.Decode(data)
   if err != nil {
      t.Fatal(err)
   }
   data, err = os.ReadFile(tester.dir + "signing_key.txt")
   if err != nil {
      t.Fatal(err)
   }
   device.SigningKey.LoadBytes(data)
   data, err = os.ReadFile(tester.dir + "encrypt_key.txt")
   if err != nil {
      t.Fatal(err)
   }
   device.EncryptKey.LoadBytes(data)
   key_id := [16]byte{1}
   envelope1, err := device.envelope(
      base64.StdEncoding.EncodeToString(key_id[:]),
   )
   if err != nil {
      t.Fatal(err)
   }
   data, err = xml.Marshal(envelope1)
   if err != nil {
      t.Fatal(err)
   }
   resp, err := http.Post(
      // https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=(persist:false,ck:AAAAAAAAAAAAAAAAAAAAAA==,ckt:aescbc)
      "https://test.playready.microsoft.com/service/rightsmanager.asmx",
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
   key, err := device.ParseLicense(data)
   if err != nil {
      t.Fatal(err)
   }
   if !bytes.Equal(key.KeyId.Guid(), key_id[:]) {
      t.Fatal(".KeyId")
   }
   println(
      hex.EncodeToString(key.Key[:]),
   )
   //if hex.EncodeToString(key.Key.Uuid()) != rakuten.key {
   //   t.Fatal(".Key")
   //}
}

func TestRakuten(t *testing.T) {
   var device LocalDevice
   data, err := os.ReadFile(tester.dir + "chain.txt")
   if err != nil {
      t.Fatal(err)
   }
   err = device.CertificateChain.Decode(data)
   if err != nil {
      t.Fatal(err)
   }
   data, err = os.ReadFile(tester.dir + "signing_key.txt")
   if err != nil {
      t.Fatal(err)
   }
   device.SigningKey.LoadBytes(data)
   data, err = os.ReadFile(tester.dir + "encrypt_key.txt")
   if err != nil {
      t.Fatal(err)
   }
   device.EncryptKey.LoadBytes(data)
   envelope1, err := device.envelope(rakuten.kid_pr)
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
   key, err := device.ParseLicense(data)
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
   // THIS URL GETS LOCKED TO DEVICE ON FIRST REQUEST
   url:     "https://prod-playready.rakuten.tv/v1/licensing/pr?uuid=1b1e3d8c-abf2-440b-a139-5621cecd13bc",
   content: "rakuten.tv/cz?content_type=movies&content_id=transvulcania-the-people-s-run",
   key:     "ab82952e8b567a2359393201e4dde4b4",
   kid_wv:  "318f7ece69afcfe3e96de31be6b77272",
   kid_pr:  "zn6PMa9p48/pbeMb5rdycg==",
}

