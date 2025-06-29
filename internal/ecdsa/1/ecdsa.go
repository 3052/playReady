package ecdsa

import (
   "crypto/sha256"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/curve"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/ecdsa"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/math"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/point"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/privatekey"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/publickey"
   "github.com/starkbank/ecdsa-go/v2/ellipticcurve/signature"
   "math/big"
)

func encrypt(m, h *publickey.PublicKey) (c1, c2 *point.Point) {
   // generator g
   g := curve.Prime256v1
   // choose an integer y
   y := big.NewInt(1)
   // compute s = h * y
   s := math.Multiply(h.Point, y, h.Curve.N, h.Curve.A, h.Curve.P)
   // compute c1 = g * y
   c1v := math.Multiply(g.G, y, g.N, g.A, g.P)
   // compute c2 = m + s
   c2v := math.Add(m.Point, s, g.A, g.P)
   return &c1v, &c2v
}

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
