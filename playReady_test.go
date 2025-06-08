package playReady

import (
   "log"
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
