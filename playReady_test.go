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

var SL2000 = device_tester{
   dir: "ignore/SL2000/",
   g1:  "g1",
   z1:  "z1",
}

var SL3000 = device_tester{
   dir: "ignore/SL3000/",
   g1:  "bgroupcert.dat",
   z1:  "zgpriv.dat",
}

var tester = SL2000

type device_tester struct {
   dir string
   g1  string
   z1  string
}

func write_file(name string, data []byte) error {
   log.Println("WriteFile", name)
   return os.WriteFile(name, data, os.ModePerm)
}

func TestChain(t *testing.T) {
   var chain1 Chain
   err := chain1.LoadFile(tester.dir + tester.g1)
   if err != nil {
      t.Fatal(err)
   }
   var z1 EcKey
   err = z1.LoadFile(tester.dir + tester.z1)
   if err != nil {
      t.Fatal(err)
   }
   // Fill = '@'
   // they downgrade certs from the cert digest (hash of the signing key)
   var signing_key EcKey
   err = signing_key.New()
   if err != nil {
      t.Fatal(err)
   }
   // Fill = '!'
   var encrypt_key EcKey
   err = encrypt_key.New()
   if err != nil {
      t.Fatal(err)
   }
   err = chain1.CreateLeaf(z1, signing_key, encrypt_key)
   if err != nil {
      t.Fatal(err)
   }
   err = write_file(tester.dir+"chain.txt", chain1.Encode())
   if err != nil {
      t.Fatal(err)
   }
   err = write_file(tester.dir+"signing_key.txt", signing_key.Private())
   if err != nil {
      t.Fatal(err)
   }
   err = write_file(tester.dir+"encrypt_key.txt", encrypt_key.Private())
   if err != nil {
      t.Fatal(err)
   }
}
var device_test = struct {
   content string
   key     string
   key_id  string
   url     string
}{
   // THIS URL GETS LOCKED TO DEVICE ON FIRST REQUEST
   url:     "https://prod-playready.rakuten.tv/v1/licensing/pr?uuid=07513603-86ba-41dc-8534-a5156f46cd57",
   content: "rakuten.tv/cz?content_type=movies&content_id=transvulcania-the-people-s-run",
   key:     "ab82952e8b567a2359393201e4dde4b4",
   key_id:  "318f7ece69afcfe3e96de31be6b77272",
}

const kid = "zn6PMa9p48/pbeMb5rdycg=="

func TestLocal(t *testing.T) {
   var device LocalDevice
   device.Version = "2.0.1.3"
   err := device.CertificateChain.LoadFile(tester.dir + "chain.txt")
   if err != nil {
      t.Fatal(err)
   }
   err = device.SigningKey.LoadFile(tester.dir + "signing_key.txt")
   if err != nil {
      t.Fatal(err)
   }
   err = device.EncryptKey.LoadFile(tester.dir + "encrypt_key.txt")
   if err != nil {
      t.Fatal(err)
   }
   var value Envelope
   err = value.New(&device.CertificateChain, device.SigningKey, kid)
   if err != nil {
      t.Fatal(err)
   }
   data, err := xml.Marshal(value)
   if err != nil {
      t.Fatal(err)
   }
   resp, err := http.Post(device_test.url, "", bytes.NewReader(data))
   if err != nil {
      t.Fatal(err)
   }
   defer resp.Body.Close()
   data1, err := io.ReadAll(resp.Body)
   if err != nil {
      t.Fatal(err)
   }
   if resp.StatusCode != http.StatusOK {
      var envelope struct {
         Body struct {
            Fault struct {
               Fault string `xml:"faultstring"`
            }
         }
      }
      err = xml.Unmarshal(data1, &envelope)
      if err != nil {
         t.Fatal(err)
      }
      t.Fatal(envelope)
   }
   key, err := device.ParseLicense(string(data1))
   if err != nil {
      t.Fatal(err)
   }
   if hex.EncodeToString(key.KeyId.Encode()) != device_test.key_id {
      t.Fatal(".KeyId")
   }
   if hex.EncodeToString(key.Key.Bytes()) != device_test.key {
      t.Fatal(".Key")
   }
}
