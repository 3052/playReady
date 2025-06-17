package main

import (
   "41.neocities.org/playReady"
   "crypto/elliptic"
   "fmt"
   "github.com/deatil/go-cryptobin/pubkey/elgamalecc"
)

func main() {
   key, err := elgamalecc.GenerateKey(playReady.Fill('!'), elliptic.P256())
   if err != nil {
      panic(err)
   }
   c1x, c1y, c2, err := elgamalecc.Encrypt(
      playReady.Fill('!'), &key.PublicKey, []byte("hello world"),
   )
   if err != nil {
      panic(err)
   }
   data, err := elgamalecc.Decrypt(key, c1x, c1y, c2)
   if err != nil {
      panic(err)
   }
   fmt.Printf("%q\n", data)
}
