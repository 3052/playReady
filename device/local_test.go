package device

import (
   "41.neocities.org/playReady/header"
   "net/http"
   "os"
   "strings"
   "testing"
)

var DeviceTest = struct {
   content string
   key     string
   key_id  string
   url     string
}{
   content: "rakuten.tv/cz?content_type=movies&content_id=transvulcania-the-people-s-run",
   key:     "ab82952e8b567a2359393201e4dde4b4",
   key_id:  "318f7ece69afcfe3e96de31be6b77272",
   url:     "https://prod-playready.rakuten.tv/v1/licensing/pr?uuid=473f5e6a-5b64-41f7-a8c7-8c3f2ab5f80b",
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
   err := device.Load("../ignore")
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
      //device_test.url,
      "https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=(persist:false,ckt:aesctr)",
      "text/xml; charset=UTF-8",
      strings.NewReader(challenge),
   )
   if err != nil {
      t.Fatal(err)
   }
   err = resp.Write(os.Stdout)
   if err != nil {
      t.Fatal(err)
   }
}
