package ecdsa

import (
   "crypto/ecdsa"
   "crypto/elliptic"
   "math/big"
)

func func0(data []byte) (*big.Int, *big.Int) {
   x := new(big.Int).SetBytes(data[:32])
   y := new(big.Int).SetBytes(data[32:])
   return x, y
}

// wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
func func1() ([]byte, error) {
   var (
      fill filler = '!'
      data [32]byte
   )
   fill.Read(data[:])
   var public ecdsa.PublicKey
   public.Curve = elliptic.P256()
   var private ecdsa.PrivateKey
   //////////////////////////////////////////////////////////////////////////////
   // the following line is deprecated
   // August 2025 we will have this
   // pkg.go.dev/crypto/ecdsa@go1.25rc1#ParseRawPrivateKey
   // but until then we need something else
   public.X, public.Y = public.Curve.ScalarBaseMult(data[:])
   //////////////////////////////////////////////////////////////////////////////
   private.D = new(big.Int).SetBytes(data[:])
   private.PublicKey = public
   r, s, err := ecdsa.Sign(fill, &private, data[:])
   if err != nil {
      return nil, err
   }
   return append(r.Bytes(), s.Bytes()...), nil
}

type filler byte

func (f filler) Read(data []byte) (int, error) {
   for index := range data {
      data[index] = byte(f)
   }
   return len(data), nil
}
