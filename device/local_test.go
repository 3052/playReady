package device

import (
   "41.neocities.org/playReady/header"
   "encoding/hex"
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
   content: "rakuten.tv/cz?content_type=movies&content_id=transvulcania-the-people-s-run",
   key:     "ab82952e8b567a2359393201e4dde4b4",
   key_id:  "318f7ece69afcfe3e96de31be6b77272",
   url:     "https://prod-playready.rakuten.tv/v1/licensing/pr?uuid=af8ce3fb-ad12-4b34-920b-60f1afecacb9",
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

func Test(t *testing.T) {
   var device LocalDevice
   err := device.Load("../hisense")
   if err != nil {
      t.Fatal(err)
   }
   var head header.Header
   err = head.ParseWrm(wrm)
   if err != nil {
      t.Fatal(err)
   }
   challenge, err := device.GetChallenge(head)
   if err != nil {
      t.Fatal(err)
   }
   resp, err := http.Post(
      device_test.url, "text/xml; charset=UTF-8", strings.NewReader(challenge),
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
      t.Fatal(string(data))
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
