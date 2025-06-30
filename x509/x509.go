package x509

import (
   "crypto/ecdsa"
   "crypto/x509"
   "encoding/asn1"
   "encoding/pem"
)

func (e *ecPrivateKey) New(key []byte) {
   e.Version = 1
   e.PrivateKey = key
   e.NamedCurveOid = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
}

type ecPrivateKey struct {
   Version       int
   PrivateKey    []byte
   NamedCurveOid asn1.ObjectIdentifier `asn1:"explicit"`
}

func (e *ecPrivateKey) ecdsa() (*ecdsa.PrivateKey, error) {
   data, err := asn1.Marshal(*e)
   if err != nil {
      return nil, err
   }
   return x509.ParseECPrivateKey(data)
}

func pemDecode(key []byte) (*ecdsa.PrivateKey, error) {
   block, _ := pem.Decode(key)
   return x509.ParseECPrivateKey(block.Bytes)
}

func (e *ecPrivateKey) pem() ([]byte, error) {
   data, err := asn1.Marshal(*e)
   if err != nil {
      return nil, err
   }
   data = pem.EncodeToMemory(&pem.Block{
      Type: "EC PRIVATE KEY",
      Bytes: data,
   })
   return data, nil
}
