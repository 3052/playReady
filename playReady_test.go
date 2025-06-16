package playReady

import (
   "bytes"
   "encoding/hex"
   "encoding/xml"
   "io"
   "log"
   "net/http"
   "os"
   "testing"
)

func TestKey(t *testing.T) {
   var device LocalDevice
   data, err := os.ReadFile(SL2000.dir + "chain.txt")
   if err != nil {
      t.Fatal(err)
   }
   err = device.CertificateChain.Decode(data)
   if err != nil {
      t.Fatal(err)
   }
   data, err = os.ReadFile(SL2000.dir + "signing_key.txt")
   if err != nil {
      t.Fatal(err)
   }
   device.SigningKey.unmarshal(data)
   data, err = os.ReadFile(SL2000.dir + "encrypt_key.txt")
   if err != nil {
      t.Fatal(err)
   }
   device.EncryptKey.unmarshal(data)
   for _, test := range tests {
      envelope, err := NewEnvelope(&device, test.kid_pr)
      if err != nil {
         t.Fatal(err)
      }
      data, err = xml.Marshal(envelope)
      if err != nil {
         t.Fatal(err)
      }
      func() {
         log.Print(test.url)
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
      var lic license
      err = lic.decrypt(device.EncryptKey, data)
      if err != nil {
         t.Fatal(err)
      }
      if hex.EncodeToString(lic.contentKey.KeyID.UUID()) != test.kid_wv {
         t.Fatalf(
            ".KeyID %x %x",
            lic.contentKey.KeyID.GUID(),
            lic.contentKey.KeyID.UUID(),
         )
      }
      if hex.EncodeToString(lic.contentKey.Key[:]) != test.key {
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
   var chain1 Chain
   err = chain1.Decode(data)
   if err != nil {
      t.Fatal(err)
   }
   data, err = os.ReadFile(SL2000.dir + SL2000.z1)
   if err != nil {
      t.Fatal(err)
   }
   var z1 EcKey
   z1.unmarshal(data)
   // they downgrade certs from the cert digest (hash of the signing key)
   var signing_key EcKey
   err = signing_key.New()
   if err != nil {
      t.Fatal(err)
   }
   var encrypt_key EcKey
   err = encrypt_key.New()
   if err != nil {
      t.Fatal(err)
   }
   err = chain1.CreateLeaf(z1, signing_key, encrypt_key)
   if err != nil {
      t.Fatal(err)
   }
   err = write_file(SL2000.dir+"chain.txt", chain1.Encode())
   if err != nil {
      t.Fatal(err)
   }
   err = write_file(SL2000.dir+"signing_key.txt", signing_key.Private())
   if err != nil {
      t.Fatal(err)
   }
   err = write_file(SL2000.dir+"encrypt_key.txt", encrypt_key.Private())
   if err != nil {
      t.Fatal(err)
   }
}

func write_file(name string, data []byte) error {
   log.Println("WriteFile", name)
   return os.WriteFile(name, data, os.ModePerm)
}
