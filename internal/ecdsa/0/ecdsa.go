package ecdsa

import (
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/sha256"
   "math/big"
)

func sign() (r, s, x, y *big.Int, err error) {
   var (
      fill filler = '!'
      secret [32]byte
   )
   fill.Read(secret[:])
   var public ecdsa.PublicKey
   public.Curve = elliptic.P256()
   var private ecdsa.PrivateKey
   //////////////////////////////////////////////////////////////////////////////
   // the following line is deprecated
   // August 2025 we will have this
   // pkg.go.dev/crypto/ecdsa@go1.25rc1#ParseRawPrivateKey
   // but until then we need something else
   public.X, public.Y = public.Curve.ScalarBaseMult(secret[:])
   //////////////////////////////////////////////////////////////////////////////
   private.D = new(big.Int).SetBytes(secret[:])
   private.PublicKey = public
   hash := sha256.Sum256([]byte("hello world"))
   r, s, err = ecdsa.Sign(fill, &private, hash[:])
   if err != nil {
      return
   }
   return r, s, public.X, public.Y, nil
}

func verify(r, s, x, y *big.Int) bool {
   publicKey := ecdsa.PublicKey{
      Curve: elliptic.P256(), // Assuming P256 curve
      X: x,
      Y: y,
   }
   hash := sha256.Sum256([]byte("hello world"))
   return ecdsa.Verify(&publicKey, hash[:], r, s)
}

type filler byte

func (f filler) Read(data []byte) (int, error) {
   for index := range data {
      data[index] = byte(f)
   }
   return len(data), nil
}

func public(data []byte) (*big.Int, *big.Int) {
   x := new(big.Int).SetBytes(data[:32])
   y := new(big.Int).SetBytes(data[32:])
   return x, y
}
