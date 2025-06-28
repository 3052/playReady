package ecdsa

import (
   "crypto/sha256"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/curve"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/ecdsa"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/point"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/privatekey"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/publickey"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/signature"
   "math/big"
)

func verify(r, s, x, y *big.Int) bool {
   hash := sha256.Sum256([]byte("hello world"))
   return ecdsa.Verify(
      string(hash[:]),
      signature.Signature{*r, *s},
      &publickey.PublicKey{
         Curve: curve.Prime256v1,
         Point: point.Point{
            X: x,
            Y: y,
         },
      },
   )
}

func sign() (r, s, x, y *big.Int) {
   var (
      fill filler = '!'
      secret [32]byte
   )
   fill.Read(secret[:])
   var private privatekey.PrivateKey
   private.Curve = curve.Prime256v1
   private.Secret = new(big.Int).SetBytes(secret[:])
   hash := sha256.Sum256([]byte("hello world"))
   sig := ecdsa.Sign(string(hash[:]), &private)
   public := private.PublicKey()
   return &sig.R, &sig.S, public.Point.X, public.Point.Y
}

type filler byte

func (f filler) Read(data []byte) (int, error) {
   for index := range data {
      data[index] = byte(f)
   }
   return len(data), nil
}
