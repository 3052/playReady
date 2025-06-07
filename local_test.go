package playReady

import (
   "41.neocities.org/playReady/challenge"
   "encoding/hex"
   "encoding/xml"
   "io"
   "net/http"
   "strings"
   "testing"
)

var device_test = struct {
   content string
   key     string
   key_id  string
   url     string
}{
   // THIS URL GETS LOCKED TO DEVICE ON FIRST REQUEST
   url:     "https://prod-playready.rakuten.tv/v1/licensing/pr?uuid=f2296077-3209-40ee-b3ee-33482b2e2d72",
   content: "rakuten.tv/cz?content_type=movies&content_id=transvulcania-the-people-s-run",
   key:     "ab82952e8b567a2359393201e4dde4b4",
   key_id:  "318f7ece69afcfe3e96de31be6b77272",
}

const kid = "zn6PMa9p48/pbeMb5rdycg=="

func Test(t *testing.T) {
   var device LocalDevice
   err := device.Load("ignore")
   if err != nil {
      t.Fatal(err)
   }
   data, err := challenge.New(&device.CertificateChain, device.SigningKey, kid)
   if err != nil {
      t.Fatal(err)
   }
   resp, err := http.Post(device_test.url, "", strings.NewReader(data))
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
         Body    struct {
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
   keys, err := device.ParseLicense(string(data1))
   if err != nil {
      t.Fatal(err)
   }
   key := keys[0]
   if hex.EncodeToString(key.KeyId.Encode()) != device_test.key_id {
      t.Fatal(".KeyId")
   }
   if hex.EncodeToString(key.Key.Bytes()) != device_test.key {
      t.Fatal(".Key")
   }
}
