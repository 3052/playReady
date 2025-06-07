package playReady

import (
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
   url:     "https://prod-playready.rakuten.tv/v1/licensing/pr?uuid=94eec1d1-e024-4507-9703-bead7c55ddb0",
   content: "rakuten.tv/cz?content_type=movies&content_id=transvulcania-the-people-s-run",
   key:     "ab82952e8b567a2359393201e4dde4b4",
   key_id:  "318f7ece69afcfe3e96de31be6b77272",
}

func TestLocal(t *testing.T) {
   var device LocalDevice
   err := device.Load("ignore")
   if err != nil {
      t.Fatal(err)
   }
   var head Header
   err = head.ParseWrm(wrm)
   if err != nil {
      t.Fatal(err)
   }
   challenge, err := device.GetChallenge(head)
   if err != nil {
      t.Fatal(err)
   }
   resp, err := http.Post(
      device_test.url, "", strings.NewReader(challenge),
   )
   if err != nil {
      t.Fatal(err)
   }
   defer resp.Body.Close()
   data, err := io.ReadAll(resp.Body)
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
      err = xml.Unmarshal(data, &envelope)
      if err != nil {
         t.Fatal(err)
      }
      t.Fatal(envelope)
   }
   keys, err := device.ParseLicense(string(data))
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

const wrm = `
<WRMHEADER xmlns="http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader" version="4.0.0.0">
   <DATA>
      <PROTECTINFO>
         <KEYLEN>16</KEYLEN>
         <ALGID>AESCTR</ALGID>
      </PROTECTINFO>
      <KID>zn6PMa9p48/pbeMb5rdycg==</KID>
      <CHECKSUM>YbomCXHUUNo=</CHECKSUM>
   </DATA>
</WRMHEADER>
`
