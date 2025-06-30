package x509

import (
   "bytes"
   "testing"
)

func TestPkcs8(t *testing.T) {
   data := bytes.Repeat([]byte{1}, 32)
   var key ecPrivateKey
   key.New(data)
   pkcs8, err := key.pkcs8()
   if err != nil {
      t.Fatal(err)
   }
   ecdsa, err := pkcs8.ecdsa()
   if err != nil {
      t.Fatal(err)
   }
   if !bytes.Equal(ecdsa.D.Bytes(), data) {
      t.Fatal("!bytes.Equal")
   }
}

func TestEc(t *testing.T) {
   data := bytes.Repeat([]byte{1}, 32)
   var key ecPrivateKey
   key.New(data)
   ecdsa, err := key.ecdsa()
   if err != nil {
      t.Fatal(err)
   }
   if !bytes.Equal(ecdsa.D.Bytes(), data) {
      t.Fatal("!bytes.Equal")
   }
}
