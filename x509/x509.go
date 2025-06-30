package x509

import (
   "crypto/ecdsa"
   "crypto/x509"
   "crypto/x509/pkix"
   "encoding/asn1"
   "errors"
)

type ecPrivateKey struct {
   Version       int
   PrivateKey    []byte
   NamedCurveOid asn1.ObjectIdentifier `asn1:"explicit"`
}

func (e *ecPrivateKey) New(key []byte) {
   e.Version = 1
   e.PrivateKey = key
   e.NamedCurveOid = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
}

func (e *ecPrivateKey) ecdsa() (*ecdsa.PrivateKey, error) {
   data, err := asn1.Marshal(*e)
   if err != nil {
      return nil, err
   }
   return x509.ParseECPrivateKey(data)
}
