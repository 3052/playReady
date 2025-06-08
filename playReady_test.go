package playReady

import (
   "bytes"
   "crypto/aes"
   "crypto/cipher"
   "github.com/deatil/go-cryptobin/cryptobin/crypto"
   "testing"
)

func TestCbc(t *testing.T) {
   data := []byte{2}
   var (
      key [16]byte
      iv  [16]byte
   )
   //////////////////////////////////////////////////////
   data1 := append(data, bytes.Repeat([]byte{15}, 15)...)
   block, err := aes.NewCipher(key[:])
   if err != nil {
      t.Fatal(err)
   }
   cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(data1, data1)
   //////////////////////////////////////////////////////////////
   bin := crypto.FromBytes(data).
      WithKey(key[:]).
      WithIv(iv[:]).
      Aes().CBC().PKCS7Padding().
      Encrypt()
   if err := bin.Error(); err != nil {
      t.Fatal(err)
   }
   if !bytes.Equal(bin.ToBytes(), data1) {
      t.Fatal("!bytes.Equal")
   }
}
