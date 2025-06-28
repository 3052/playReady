package ecdsa

import (
   "errors"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/curve"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/ecdsa"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/privatekey"
   "math/big"
)

func func2() ([]byte, error) {
   var (
      fill filler = '!'
      data [32]byte
   )
   fill.Read(data[:])
   var private privatekey.PrivateKey
   private.Curve = curve.Prime256v1
   private.Secret = new(big.Int).SetBytes(data[:])
   sig := ecdsa.Sign(string(data[:]), &private)
   public := private.PublicKey()
   if !ecdsa.Verify(string(data[:]), sig, &public) {
      return nil, errors.New("Verify")
   }
   return append(sig.R.Bytes(), sig.S.Bytes()...), nil
}
