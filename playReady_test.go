package playReady

import (
   "bytes"
   "encoding/hex"
   "errors"
   "io"
   "log"
   "math/big"
   "net/http"
   "net/url"
   "os"
   "slices"
   "testing"
)

func TestWmrm(t *testing.T) {
   c, err := p256().eg().Encrypt(
      p256().G,
      *wmrmPublicKey(),
      big.NewInt(1),
   )
   if err != nil {
      t.Fatal(err)
   }
   data := slices.Concat(
      c[0].X.Bytes(), c[0].Y.Bytes(), c[1].X.Bytes(), c[1].Y.Bytes(),
   )
   log.Printf("%x\n", data)
}

var device = SL2000

var key_tests = []struct {
   key      string
   kid_uuid string
   req      func(*http.Request, string) error
}{
   {
      key:      "00000000000000000000000000000000",
      kid_uuid: "10000000000000000000000000000000",
      req: func(req *http.Request, _ string) error {
         req.URL = &url.URL{
            Scheme:   "https",
            Host:     "test.playready.microsoft.com",
            Path:     "/service/rightsmanager.asmx",
            RawQuery: "cfg=ck:AAAAAAAAAAAAAAAAAAAAAA==,ckt:aescbc",
         }
         return nil
      },
   },
   {
      kid_uuid: "b70c0730222846d6884befdc96186cf4",
      key:      "3bc167f72090d429d8f3f987686f1127",
      req: func(req *http.Request, home string) error {
         data, err := os.ReadFile(home + "/media/paramount/PlayReady")
         if err != nil {
            return err
         }
         req.Header.Set("authorization", "Bearer "+string(data))
         req.URL = &url.URL{
            Scheme: "https",
            Host:   "cbsi.live.ott.irdeto.com",
            Path:   "/playready/rightsmanager.asmx",
            RawQuery: url.Values{
               "AccountId": {"cbsi"},
               "ContentId": {"wjQ4RChi6BHHu4MVTncppVuCwu44uq2Q"},
            }.Encode(),
         }
         return nil
      },
   },
   {
      key:      "12b5853e5a54a79ab84aae29d8079283",
      kid_uuid: "20613c35d9cc4c1fa9b668182eb8fc77",
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
      kid_uuid: "154978ca206a4910b58a63896e1d7ba2",
      key:      "88733937eb60a9620586c7b1024a1e98",
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
      key: "67376174a357f3ec9c1466055de9551d",
      // below is FHD (1920x1080), UHD needs SL3000
      kid_uuid: "010521b274da1acbbd3c6f124a238c67",
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
      kid_uuid: "77890254eb7247ed9cc5680790b50a27",
      key:      "98b703d07129b5f34136cec75954a8de",
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
      key:      "ab82952e8b567a2359393201e4dde4b4",
      kid_uuid: "318f7ece69afcfe3e96de31be6b77272",
      req: func(req *http.Request, home string) error {
         data, err := os.ReadFile(home + "/media/rakuten/PlayReady")
         if err != nil {
            return err
         }
         req.URL, err = url.Parse(string(data))
         return err
      },
   },
}

func TestKey(t *testing.T) {
   log.SetFlags(log.Ltime)
   data, err := os.ReadFile(device.folder + "certificate")
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
   data, err = os.ReadFile(device.folder + "signEncryptKey")
   if err != nil {
      t.Fatal(err)
   }
   signEncryptKey := new(big.Int).SetBytes(data)
   for _, test := range key_tests[:1] {
      kid, err := hex.DecodeString(test.kid_uuid)
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
      var licenseVar License
      coord, err := licenseVar.Decrypt(data, signEncryptKey)
      if err != nil {
         t.Fatal(err)
      }
      UuidOrGuid(licenseVar.ContentKey.KeyId[:])
      if hex.EncodeToString(licenseVar.ContentKey.KeyId[:]) != test.kid_uuid {
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

func TestLeaf(t *testing.T) {
   data, err := os.ReadFile(device.folder + device.g1)
   if err != nil {
      t.Fatal(err)
   }
   var certificate Chain
   err = certificate.Decode(data)
   if err != nil {
      t.Fatal(err)
   }
   data, err = os.ReadFile(device.folder + device.z1)
   if err != nil {
      t.Fatal(err)
   }
   z1 := new(big.Int).SetBytes(data)
   signEncryptKey := big.NewInt('!')
   err = certificate.Leaf(z1, signEncryptKey)
   if err != nil {
      t.Fatal(err)
   }
   err = write_file(device.folder+"certificate", certificate.Encode())
   if err != nil {
      t.Fatal(err)
   }
   err = write_file(device.folder+"signEncryptKey", signEncryptKey.Bytes())
   if err != nil {
      t.Fatal(err)
   }
}

type device_config struct {
   folder string
   g1     string
   z1     string
}

var SL2000 = device_config{
   folder: "ignore/",
   g1:     "g1",
   z1:     "z1",
}

var SL3000 = device_config{
   folder: "ignore/",
   g1:     "bgroupcert.dat",
   z1:     "zgpriv.dat",
}
