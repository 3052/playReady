package x509

import (
   "bytes"
   "testing"
)

func TestPem(t *testing.T) {
   data := bytes.Repeat([]byte{1}, 32)
   var key ecPrivateKey
   key.New(data)
   data1, err := key.pem()
   if err != nil {
      t.Fatal(err)
   }
   ecdsa, err := pemDecode(data1)
   if err != nil {
      t.Fatal(err)
   }
   if !bytes.Equal(ecdsa.D.Bytes(), data) {
      t.Fatal("!bytes.Equal")
   }
}

func TestEcdsa(t *testing.T) {
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
