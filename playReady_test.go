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

var key_tests = []struct {
   key    string
   kid_wv string
   url    func(string) (string, error)
}{
   {
      key:    "67376174a357f3ec9c1466055de9551d",
      // below is FHD (1920x1080), UHD needs SL3000
      kid_wv: "010521b274da1acbbd3c6f124a238c67",
      url: func(home string) (string, error) {
         data, err := os.ReadFile(home + "/media/max/PlayReady")
         if err != nil {
            return "", err
         }
         return string(data), nil
      },
   },
   {
      key:    "12b5853e5a54a79ab84aae29d8079283",
      kid_wv: "20613c35d9cc4c1fa9b668182eb8fc77",
      url: func(home string) (string, error) {
         data, err := os.ReadFile(home + "/media/hulu/DashPrServer")
         if err != nil {
            return "", err
         }
         return string(data), nil
      },
   },
   {
      key:    "ab82952e8b567a2359393201e4dde4b4",
      kid_wv: "318f7ece69afcfe3e96de31be6b77272",
      url: func(home string) (string, error) {
         data, err := os.ReadFile(home + "/media/rakuten/Pr")
         if err != nil {
            return "", err
         }
         return string(data), nil
      },
   },
   {
      key:    "00000000000000000000000000000000",
      kid_wv: "10000000000000000000000000000000",
      url: func(string) (string, error) {
         return "https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=ck:AAAAAAAAAAAAAAAAAAAAAA==,ckt:aescbc", nil
      },
   },
}
func TestKey(t *testing.T) {
   log.SetFlags(log.Ltime)
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
   home, err := os.UserHomeDir()
   if err != nil {
      t.Fatal(err)
   }
   for _, test := range key_tests {
      url, err := test.url(home)
      if err != nil {
         t.Fatal(err)
      }
      log.Print(url)
      kid, err := hex.DecodeString(test.kid_wv)
      if err != nil {
         t.Fatal(err)
      }
      UuidOrGuid(kid)
      data, err = certificate.RequestBody(signEncryptKey, kid)
      if err != nil {
         t.Fatal(err)
      }
      data, err = post(url, data)
      if err != nil {
         t.Fatal(err)
      }
      var license1 License
      err = license1.Decrypt(signEncryptKey, data)
      if err != nil {
         t.Fatal(err)
      }
      content := license1.ContentKey
      UuidOrGuid(content.KeyId[:])
      if hex.EncodeToString(content.KeyId[:]) != test.kid_wv {
         t.Fatal(".KeyId")
      }
      if hex.EncodeToString(content.Key()) != test.key {
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

var SL2000 = struct {
   dir string
   g1  string
   z1  string
}{
   dir: "ignore/",
   g1:  "g1",
   z1:  "z1",
}
