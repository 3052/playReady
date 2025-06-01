package crypto

import (
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/rand"
)

type XmlKey struct {
   PublicKey     ecdsa.PublicKey
   AesKey, AesIv [16]byte
}

func (x *XmlKey) New() error {
   key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

   if err != nil {
      return err
   }

   x.PublicKey = key.PublicKey

   Aes := x.PublicKey.X.Bytes()

   n := copy(x.AesIv[:], Aes)

   Aes = Aes[n:]

   copy(x.AesKey[:], Aes)

   return nil
}
