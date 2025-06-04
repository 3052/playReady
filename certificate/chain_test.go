package certificate

import (
   "41.neocities.org/playReady/crypto"
   "log"
   "os"
   "testing"
)

func Test(t *testing.T) {
   var chain1 Chain
   err := chain1.LoadFile("../ignore/bgroupcert.dat")
   if err != nil {
      t.Fatal(err)
   }
   var z1 crypto.EcKey
   err = z1.LoadFile("../ignore/zgpriv.dat")
   if err != nil {
      t.Fatal(err)
   }
   // they downgrade certs from the cert digest (hash of the signing key)
   var signing_key crypto.EcKey
   err = signing_key.New()
   if err != nil {
      t.Fatal(err)
   }
   var encrypt_key crypto.EcKey
   err = encrypt_key.New()
   if err != nil {
      t.Fatal(err)
   }
   err = chain1.CreateLeaf(z1, signing_key, encrypt_key)
   if err != nil {
      t.Fatal(err)
   }
   err = write_file("../ignore/Chain", chain1.Encode())
   if err != nil {
      t.Fatal(err)
   }
   err = write_file("../ignore/SigningKey", signing_key.Private())
   if err != nil {
      t.Fatal(err)
   }
   err = write_file("../ignore/EncryptKey", encrypt_key.Private())
   if err != nil {
      t.Fatal(err)
   }
}

func write_file(name string, data []byte) error {
   log.Println("WriteFile", name)
   return os.WriteFile(name, data, os.ModePerm)
}
