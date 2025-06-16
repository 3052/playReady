package playReady

import (
   "bytes"
   "encoding/hex"
   "io"
   "log"
   "net/http"
   "os"
   "testing"
)

func TestKey(t *testing.T) {
   data, err := os.ReadFile(SL2000.dir + "chain.txt")
   if err != nil {
      t.Fatal(err)
   }
   var certificate Chain
   err = certificate.Decode(data)
   if err != nil {
      t.Fatal(err)
   }
   data, err = os.ReadFile(SL2000.dir + "signing_key.txt")
   if err != nil {
      t.Fatal(err)
   }
   var signing EcKey
   signing.decode(data)
   data, err = os.ReadFile(SL2000.dir + "encrypt_key.txt")
   if err != nil {
      t.Fatal(err)
   }
   var encrypt EcKey
   encrypt.decode(data)
   for _, test := range tests {
      log.Print(test.url)
      data, err = certificate.requestBody(signing, test.kid_pr)
      if err != nil {
         t.Fatal(err)
      }
      func() {
         resp, err := http.Post(test.url, "text/xml", bytes.NewReader(data))
         if err != nil {
            t.Fatal(err)
         }
         defer resp.Body.Close()
         data, err = io.ReadAll(resp.Body)
         if err != nil {
            t.Fatal(err)
         }
      }()
      var license1 license
      err = license1.decrypt(encrypt, data)
      if err != nil {
         t.Fatal(err)
      }
      content := license1.contentKey
      if hex.EncodeToString(content.KeyID.UUID()) != test.kid_wv {
         t.Fatal(".KeyID")
      }
      if hex.EncodeToString(content.Key[:]) != test.key {
         t.Fatal(".Key")
      }
   }
}

var tests = []struct {
   key    string
   kid_pr string
   kid_wv string
   url    string
}{
   {
      key:    "ab82952e8b567a2359393201e4dde4b4",
      kid_pr: "zn6PMa9p48/pbeMb5rdycg==",
      kid_wv: "318f7ece69afcfe3e96de31be6b77272",
      url:    "https://prod-playready.rakuten.tv/v1/licensing/pr?uuid=702696eb-505d-4736-8c7c-297f9de5e9a7",
   },
   {
      key:    "00000000000000000000000000000000",
      kid_pr: "AAAAEAAAAAAAAAAAAAAAAA==",
      kid_wv: "10000000000000000000000000000000",
      url:    "https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=(persist:false,ck:AAAAAAAAAAAAAAAAAAAAAA==,ckt:aescbc)",
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

func TestChain(t *testing.T) {
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
   z1.decode(data)
   // they downgrade certs from the cert digest (hash of the signing key)
   var signing EcKey
   err = signing.New()
   if err != nil {
      t.Fatal(err)
   }
   var encrypt EcKey
   err = encrypt.New()
   if err != nil {
      t.Fatal(err)
   }
   err = certificate.CreateLeaf(z1, signing, encrypt)
   if err != nil {
      t.Fatal(err)
   }
   err = write_file(SL2000.dir+"chain.txt", certificate.Encode())
   if err != nil {
      t.Fatal(err)
   }
   err = write_file(SL2000.dir+"signing_key.txt", signing.Private())
   if err != nil {
      t.Fatal(err)
   }
   err = write_file(SL2000.dir+"encrypt_key.txt", encrypt.Private())
   if err != nil {
      t.Fatal(err)
   }
}

func write_file(name string, data []byte) error {
   log.Println("WriteFile", name)
   return os.WriteFile(name, data, os.ModePerm)
}
