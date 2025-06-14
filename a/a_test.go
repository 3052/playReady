package a

import (
   "crypto/ecdsa"
   "crypto/elliptic"
   "encoding/hex"
   "fmt"
   "math/big"
   "testing"
)

func Test(t *testing.T) {
   data, err := hex.DecodeString(wmrm_public_key)
   if err != nil {
      t.Fatal(err)
   }
   x := new(big.Int).SetBytes(data[:32])
   y := new(big.Int).SetBytes(data[32:])
   fmt.Println(x, y)
   
   var public ecdsa.PublicKey
   public.Curve = elliptic.P256()
   public.X, public.Y = public.Curve.ScalarBaseMult(data)
   fmt.Printf("%+v\nn", public)
}
