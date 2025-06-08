package playReady

import (
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/x509"
   "encoding/pem"
   "math/big"
   "os"
)

func (e *EcKey) LoadBytes(data []byte) {
   var public ecdsa.PublicKey
   public.Curve = elliptic.P256()
   public.X, public.Y = public.Curve.ScalarBaseMult(data)
   var private ecdsa.PrivateKey
   private.D = new(big.Int).SetBytes(data)
   private.PublicKey = public
   e.Key = &private
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

func (e *EcKey) PublicBytes() []byte {
   SigningX, SigningY := e.Key.PublicKey.X.Bytes(), e.Key.PublicKey.Y.Bytes()
   SigningPublicKey := SigningX
   SigningPublicKey = append(SigningPublicKey, SigningY...)
   return SigningPublicKey
}

func (e EcKey) Private() []byte {
   var data [32]byte
   e.Key.D.FillBytes(data[:])
   return data[:]
}

type EcKey struct {
   Key *ecdsa.PrivateKey
}

func (e *EcKey) New() error {
   var err error
   e.Key, err = ecdsa.GenerateKey(elliptic.P256(), Fill)
   if err != nil {
      return err
   }
   return nil
}
