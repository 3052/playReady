package playReady

import (
   "41.neocities.org/playReady/challenge"
   "bytes"
   "encoding/hex"
   "encoding/xml"
   "io"
   "net/http"
   "testing"
)

var folder = SL2000
//var folder = SL3000

var SL2000 = "ignore/SL2000/"

var SL3000 = "ignore/SL3000/"

var device_test = struct {
   content string
   key     string
   key_id  string
   url     string
}{
   // THIS URL GETS LOCKED TO DEVICE ON FIRST REQUEST
   url:     "https://prod-playready.rakuten.tv/v1/licensing/pr?uuid=07513603-86ba-41dc-8534-a5156f46cd57",
   content: "rakuten.tv/cz?content_type=movies&content_id=transvulcania-the-people-s-run",
   key:     "ab82952e8b567a2359393201e4dde4b4",
   key_id:  "318f7ece69afcfe3e96de31be6b77272",
}

const kid = "zn6PMa9p48/pbeMb5rdycg=="

func Test(t *testing.T) {
   var device LocalDevice
   device.Version = "2.0.1.3"
   err := device.CertificateChain.LoadFile(folder + "chain.txt")
   if err != nil {
      t.Fatal(err)
   }
   err = device.SigningKey.LoadFile(folder + "signing_key.txt")
   if err != nil {
      t.Fatal(err)
   }
   err = device.EncryptKey.LoadFile(folder + "encrypt_key.txt")
   if err != nil {
      t.Fatal(err)
   }
   var envelope challenge.Envelope
   err = envelope.New(&device.CertificateChain, device.SigningKey, kid)
   if err != nil {
      t.Fatal(err)
   }
   data, err := xml.Marshal(envelope)
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
   key, err := device.ParseLicense(string(data1))
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
