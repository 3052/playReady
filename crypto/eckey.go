package crypto

import (
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/rand"
   "crypto/x509"
   "encoding/pem"
   "math/big"
   "os"
)

type EcKey struct {
   Key *ecdsa.PrivateKey
}

func (e *EcKey) New() error {
   key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

   if err != nil {
      return err
   }

   e.Key = key
   return nil
}

func (e *EcKey) LoadFile(path string) error {
   keyFile, err := os.ReadFile(path)

   if err != nil {
      return err
   }

   block, _ := pem.Decode(keyFile)

   if block == nil {
      e.LoadBytes(keyFile)
      return nil
   }

   key, err := x509.ParsePKCS8PrivateKey(block.Bytes)

   if err != nil {
      return err
   }

   e.Key = key.(*ecdsa.PrivateKey)
   return nil
}

func (e *EcKey) LoadBytes(data []byte) error {
   var public ecdsa.PublicKey
   public.Curve = elliptic.P256()
   public.X, public.Y = public.Curve.ScalarBaseMult(data)
   var private ecdsa.PrivateKey
   private.D = new(big.Int).SetBytes(data)
   private.PublicKey = public

   e.Key = &private

   return nil
}

func (e *EcKey) PublicBytes() []byte {
   SigningX, SigningY := e.Key.PublicKey.X.Bytes(), e.Key.PublicKey.Y.Bytes()

   SigningPublicKey := SigningX
   SigningPublicKey = append(SigningPublicKey, SigningY...)

   return SigningPublicKey
}
