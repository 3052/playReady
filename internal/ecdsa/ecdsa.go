package ecdsa

import (
   "crypto/ecdsa"
   "crypto/elliptic"
   "math/big"
)

// wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
func func1() ([]byte, error) {
   var (
      fill filler = '!'
      data [32]byte
   )
   fill.Read(data[:])
   var public ecdsa.PublicKey
   public.Curve = elliptic.P256()
   public.X, public.Y = public.Curve.ScalarBaseMult(data[:])
   var private ecdsa.PrivateKey
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

func func0(data []byte) (*big.Int, *big.Int) {
   x := new(big.Int).SetBytes(data[:32])
   y := new(big.Int).SetBytes(data[32:])
   return x, y
}
