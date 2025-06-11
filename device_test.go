package playReady

import (
   "bytes"
   "encoding/hex"
   "encoding/xml"
   "io"
   "net/http"
   "os"
   "testing"
)

func TestDevice(t *testing.T) {
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
   envelope1, err := device.envelope(kid)
   if err != nil {
      t.Fatal(err)
   }
   data, err = xml.Marshal(envelope1)
   if err != nil {
      t.Fatal(err)
   }
   resp, err := http.Post(device_test.url, "", bytes.NewReader(data))
   if err != nil {
      t.Fatal(err)
   }
   defer resp.Body.Close()
   data1, err := io.ReadAll(resp.Body)
   if err != nil {
      t.Fatal(err)
   }
   if resp.StatusCode != http.StatusOK {
      var envelope struct {
         Body struct {
            Fault struct {
               Fault string `xml:"faultstring"`
            }
         }
      }
      err = xml.Unmarshal(data1, &envelope)
      if err != nil {
         t.Fatal(err)
      }
      t.Fatal(envelope)
   }
   key, err := device.ParseLicense(data1)
   if err != nil {
      t.Fatal(err)
   }
   if hex.EncodeToString(key.KeyId.Encode()) != device_test.key_id {
      t.Fatal(".KeyId")
   }
   if hex.EncodeToString(key.Key.Bytes()) != device_test.key {
      t.Fatal(".Key")
   }
}
var device_test = struct {
   content string
   key     string
   key_id  string
   url     string
}{
   // THIS URL GETS LOCKED TO DEVICE ON FIRST REQUEST
   url:     "https://prod-playready.rakuten.tv/v1/licensing/pr?uuid=8e19eb98-3700-490f-97b9-dab1856eb359",
   content: "rakuten.tv/cz?content_type=movies&content_id=transvulcania-the-people-s-run",
   key:     "ab82952e8b567a2359393201e4dde4b4",
   key_id:  "318f7ece69afcfe3e96de31be6b77272",
}

const kid = "zn6PMa9p48/pbeMb5rdycg=="

