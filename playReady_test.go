package playReady

import (
   "bytes"
   "encoding/hex"
   "errors"
   "io"
   "log"
   "net/http"
   "net/url"
   "os"
   "testing"
   "math/big"
)

var key_tests = []struct {
   key    string
   kid_wv string
   req func(*http.Request, string) error
}{
   {
      key:    "12b5853e5a54a79ab84aae29d8079283",
      kid_wv: "20613c35d9cc4c1fa9b668182eb8fc77",
      req: func(req *http.Request, home string) error {
         data, err := os.ReadFile(home + "/media/hulu/PlayReady")
         if err != nil {
            return err
         }
         req.URL, err = url.Parse(string(data))
         return err
      },
   },
   {
      kid_wv: "154978ca206a4910b58a63896e1d7ba2",
      key:    "88733937eb60a9620586c7b1024a1e98",
      req: func(req *http.Request, home string) error {
         data, err := os.ReadFile(home + "/media/itv/PlayReady")
         if err != nil {
            return err
         }
         req.URL, err = url.Parse(string(data))
         return err
      },
   },
   {
      key:    "67376174a357f3ec9c1466055de9551d",
      // below is FHD (1920x1080), UHD needs SL3000
      kid_wv: "010521b274da1acbbd3c6f124a238c67",
      req: func(req *http.Request, home string) error {
         data, err := os.ReadFile(home + "/media/max/PlayReady")
         if err != nil {
            return err
         }
         req.URL, err = url.Parse(string(data))
         return err
      },
   },
   {
      kid_wv: "77890254eb7247ed9cc5680790b50a27",
      key:    "98b703d07129b5f34136cec75954a8de",
      req: func(req *http.Request, home string) error {
         data, err := os.ReadFile(home + "/media/nbc/PlayReady")
         if err != nil {
            return err
         }
         req.URL, err = url.Parse(string(data))
         return err
      },
   },
   {
      kid_wv: "5539d31134714041b4c1d362381b32d9",
      key:    "9d948d2068ba795618f5e374e41b483f",
      req: func(req *http.Request, home string) error {
         data, err := os.ReadFile(home + "/media/paramount/PlayReady")
         if err != nil {
            return err
         }
         req.Header.Set("authorization", "Bearer " + string(data))
         req.URL = &url.URL{
            Scheme: "https",
            Host: "cbsi.live.ott.irdeto.com",
            Path: "/playready/rightsmanager.asmx",
            RawQuery: url.Values{
               "AccountId": {"cbsi"},
               "ContentId": {"tOeI0WHG3icuPhCk5nkLXNmi5c4Jfx41"},
            }.Encode(),
         }
         return nil
      },
   },
   {
      key:    "ab82952e8b567a2359393201e4dde4b4",
      kid_wv: "318f7ece69afcfe3e96de31be6b77272",
      req: func(req *http.Request, home string) error {
         data, err := os.ReadFile(home + "/media/rakuten/PlayReady")
         if err != nil {
            return err
         }
         req.URL, err = url.Parse(string(data))
         return err
      },
   },
   {
      key:    "00000000000000000000000000000000",
      kid_wv: "10000000000000000000000000000000",
      req: func(req *http.Request, _ string) error {
         req.URL = &url.URL{
            Scheme: "https",
            Host: "test.playready.microsoft.com",
            Path: "/service/rightsmanager.asmx",
            RawQuery: "cfg=ck:AAAAAAAAAAAAAAAAAAAAAA==,ckt:aescbc",
         }
         return nil
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
   home, err := os.UserHomeDir()
   if err != nil {
      t.Fatal(err)
   }
   data, err = os.ReadFile(SL2000.dir + "signEncryptKey")
   if err != nil {
      t.Fatal(err)
   }
   signEncryptKey := new(big.Int).SetBytes(data)
   for _, test := range key_tests {
      kid, err := hex.DecodeString(test.kid_wv)
      if err != nil {
         t.Fatal(err)
      }
      UuidOrGuid(kid)
      data, err = certificate.RequestBody(kid, signEncryptKey)
      if err != nil {
         t.Fatal(err)
      }
      req, err := http.NewRequest("POST", "", bytes.NewReader(data))
      if err != nil {
         t.Fatal(err)
      }
      err = test.req(req, home)
      if err != nil {
         t.Fatal(err)
      }
      log.Print(req.URL)
      data, err = post(req)
      if err != nil {
         t.Fatal(err)
      }
      var lic License
      coord, err := lic.Decrypt(data, signEncryptKey)
      if err != nil {
         t.Fatal(err)
      }
      UuidOrGuid(lic.ContentKey.KeyId[:])
      if hex.EncodeToString(lic.ContentKey.KeyId[:]) != test.kid_wv {
         t.Fatal(".KeyId")
      }
      if hex.EncodeToString(coord.Key()) != test.key {
         t.Fatal(".Key")
      }
   }
}

func post(req *http.Request) ([]byte, error) {
   req.Header.Set("content-type", "text/xml")
   resp, err := http.DefaultClient.Do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   data, err := io.ReadAll(resp.Body)
   if err != nil {
      return nil, err
   }
   if resp.StatusCode != http.StatusOK {
      return nil, errors.New(string(data))
   }
   return data, nil
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
   z1 := new(big.Int).SetBytes(data)
   signEncryptKey := big.NewInt('!')
   err = certificate.Leaf(z1, signEncryptKey)
   if err != nil {
      t.Fatal(err)
   }
   err = write_file(SL2000.dir+"certificate", certificate.Encode())
   if err != nil {
      t.Fatal(err)
   }
   err = write_file(SL2000.dir+"signEncryptKey", signEncryptKey.Bytes())
   if err != nil {
      t.Fatal(err)
   }
}
