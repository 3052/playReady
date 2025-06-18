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

func write_file(name string, data []byte) error {
   log.Println("WriteFile", name)
   return os.WriteFile(name, data, os.ModePerm)
}

var key_tests = []struct {
   key    string
   kid_wv string
   url    string
}{
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
   z1.decode(data)
   signEncryptKey, err := Fill('s').key()
   if err != nil {
      t.Fatal(err)
   }
   err = certificate.CreateLeaf(&z1, signEncryptKey)
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
   signEncryptKey.decode(data)
   for _, test := range key_tests {
      log.Print(test.url)
      kid, err := hex.DecodeString(test.kid_wv)
      if err != nil {
         t.Fatal(err)
      }
      UuidOrGuid(kid)
      data, err = certificate.requestBody(signEncryptKey, kid)
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
         if resp.StatusCode != http.StatusOK {
            t.Fatal(string(data))
         }
      }()
      var license1 license
      err = license1.decrypt(signEncryptKey, data)
      if err != nil {
         t.Fatal(err)
      }
      content := license1.contentKey
      UuidOrGuid(content.KeyID[:])
      if hex.EncodeToString(content.KeyID[:]) != test.kid_wv {
         t.Fatal(".KeyID")
      }
      if hex.EncodeToString(content.Key[:]) != test.key {
         t.Fatal(".Key")
      }
   }
}
