package playReady

import (
   "bytes"
   "encoding/hex"
   "errors"
   "io"
   "log"
   "net/http"
   "os"
   "testing"
)

var key_tests = []struct {
   key    string
   kid_wv string
   url    string
}{
   {
      key:    "ee0d569c019057569eaf28b988c206f6",
      kid_wv: "01038786b77fb6ca14eb864155de730e", // L1
      url:    "https://busy.any-any.prd.api.discomax.com/drm-proxy/any/drm-proxy/drm/license/play-ready?drmKeyVersion=1&auth=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHBpcmF0aW9uVGltZSI6IjIwMjUtMDYtMjRUMDQ6NDE6NDMuMTgzOTYyODYxWiIsImVkaXRJZCI6IjA2YTM4Mzk3LTg2MmQtNDQxOS1iZTg0LTA2NDE5Mzk4MjVlNyIsImFwcEJ1bmRsZSI6IiIsInBsYXRmb3JtIjoiIiwidXNlcklkIjoiVVNFUklEOmJvbHQ6MGQ0NWNjZjgtYjRhMi00MTQ3LWJiZWItYzdiY2IxNDBmMzgyIiwicHJvZmlsZUlkIjoibWl0aWdhdGVkLXByb2ZpbGUiLCJkZXZpY2VJZCI6IiEiLCJzc2FpIjp0cnVlLCJzdHJlYW1UeXBlIjoidm9kIiwiaGVhcnRiZWF0RW5hYmxlZCI6ZmFsc2V9.fC3xCPLBWzyCSeBKW1PO85f_3c8BlA2UFyO16ZO9y_4&x-wbd-tenant=beam&x-wbd-user-home-market=emea",
   },
   {
      key:    "ab82952e8b567a2359393201e4dde4b4",
      kid_wv: "318f7ece69afcfe3e96de31be6b77272",
      url:    "https://prod-playready.rakuten.tv/v1/licensing/pr?uuid=79a4952e-0e2a-41cd-b1bc-5908e0e4bbaf",
   },
   {
      key:    "00000000000000000000000000000000",
      kid_wv: "10000000000000000000000000000000",
      url:    "https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=ck:AAAAAAAAAAAAAAAAAAAAAA==,ckt:aescbc",
   },
}

var SL2000 = struct {
   dir string
   g1  string
   z1  string
}{
   dir: "ignore/",
   g1:  "g1",
   z1:  "z1",
}

func TestLeaf(t *testing.T) {
   data, err := os.ReadFile(SL2000.dir + SL2000.g1)
   if err != nil {
      t.Fatal(err)
   }
   var certificate Chain
   err = certificate.Decode(data)
   if err != nil {
      t.Fatal(err)
   }
   data, err = os.ReadFile(SL2000.dir + SL2000.z1)
   if err != nil {
      t.Fatal(err)
   }
   var z1 EcKey
   z1.Decode(data)
   signEncryptKey, err := Fill('B').Key()
   if err != nil {
      t.Fatal(err)
   }
   err = certificate.Leaf(&z1, signEncryptKey)
   if err != nil {
      t.Fatal(err)
   }
   err = write_file(SL2000.dir+"certificate", certificate.Encode())
   if err != nil {
      t.Fatal(err)
   }
   err = write_file(SL2000.dir+"signEncryptKey", signEncryptKey.Private())
   if err != nil {
      t.Fatal(err)
   }
}

func TestKey(t *testing.T) {
   data, err := os.ReadFile(SL2000.dir + "certificate")
   if err != nil {
      t.Fatal(err)
   }
   var certificate Chain
   err = certificate.Decode(data)
   if err != nil {
      t.Fatal(err)
   }
   data, err = os.ReadFile(SL2000.dir + "signEncryptKey")
   if err != nil {
      t.Fatal(err)
   }
   var signEncryptKey EcKey
   signEncryptKey.Decode(data)
   for _, test := range key_tests {
      log.Print(test.url)
      kid, err := hex.DecodeString(test.kid_wv)
      if err != nil {
         t.Fatal(err)
      }
      UuidOrGuid(kid)
      data, err = certificate.RequestBody(signEncryptKey, kid)
      if err != nil {
         t.Fatal(err)
      }
      data, err = post(test.url, data)
      if err != nil {
         t.Fatal(err)
      }
      var license1 License
      err = license1.Decrypt(signEncryptKey, data)
      if err != nil {
         t.Fatal(err)
      }
      content := license1.ContentKey
      UuidOrGuid(content.KeyID[:])
      if hex.EncodeToString(content.KeyID[:]) != test.kid_wv {
         t.Fatal(".KeyID")
      }
      if hex.EncodeToString(content.Key[:]) != test.key {
         t.Fatal(".Key")
      }
   }
}

func post(url string, body []byte) ([]byte, error) {
   resp, err := http.Post(url, "text/xml", bytes.NewReader(body))
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   body, err = io.ReadAll(resp.Body)
   if err != nil {
      return nil, err
   }
   if resp.StatusCode != http.StatusOK {
      return nil, errors.New(string(body))
   }
   return body, nil
}

func write_file(name string, data []byte) error {
   log.Println("WriteFile", name)
   return os.WriteFile(name, data, os.ModePerm)
}
