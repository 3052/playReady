package crypto

import (
   "crypto/elliptic"
   "crypto/rand"
   "math/big"
)

func random(curveData elliptic.Curve) *big.Int {
   one := big.NewInt(1)
   maxInt := new(big.Int).Sub(curveData.Params().N, one)

   r, err := rand.Int(rand.Reader, maxInt)
   if err != nil {
      panic(err)
   }

   r.Add(r, one)

   return r
}

type ElGamal struct{}

func (el ElGamal) Encrypt(PubX *big.Int, PubY *big.Int, plaintext XmlKey) []byte {
   curveData := elliptic.P256()
   Random := random(curveData)

   C1X, C1Y := curveData.ScalarMult(curveData.Params().Gx, curveData.Params().Gy, Random.Bytes())

   C2XMulti, C2YMulti := curveData.ScalarMult(PubX, PubY, Random.Bytes())

   C2X, C2Y := curveData.Add(plaintext.PublicKey.X, plaintext.PublicKey.Y, C2XMulti, C2YMulti)

   Encrypted := C1X.Bytes()
   Encrypted = append(Encrypted, C1Y.Bytes()...)
   Encrypted = append(Encrypted, C2X.Bytes()...)
   return append(Encrypted, C2Y.Bytes()...)
}

func (el ElGamal) Decrypt(ciphertext []byte, PrivateKey *big.Int) []byte {
   curveData := elliptic.P256()

   x1, y1 := new(big.Int).SetBytes(ciphertext[:32]), new(big.Int).SetBytes(ciphertext[32:64])
   x2, y2 := new(big.Int).SetBytes(ciphertext[64:96]), new(big.Int).SetBytes(ciphertext[96:128])

   SX, SY := curveData.ScalarMult(x1, y1, PrivateKey.Bytes())

   NegSY := new(big.Int).Sub(curveData.Params().P, SY)

   NegSY.Mod(NegSY, curveData.Params().P)

   PX, PY := curveData.Add(x2, y2, SX, NegSY)

   Decrypted := PX.Bytes()

   return append(Decrypted, PY.Bytes()...)
}
