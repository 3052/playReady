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

func (e *ecPrivateKey) pkcs8() (*pkcs8, error) {
   var privKey pkcs8
   oid := asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
   oidBytes, err := asn1.Marshal(oid)
   if err != nil {
      return nil, err
   }
   privKey.Algo = pkix.AlgorithmIdentifier{
      Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
      Parameters: asn1.RawValue{FullBytes: oidBytes},
   }
   privKey.PrivateKey, err = asn1.Marshal(*e)
   if err != nil {
      return nil, err
   }
   return &privKey, nil
}

type pkcs8 struct {
   Version    int
   Algo       pkix.AlgorithmIdentifier
   PrivateKey []byte
}

func (p *pkcs8) ecdsa() (*ecdsa.PrivateKey, error) {
   data, err := asn1.Marshal(*p)
   if err != nil {
      return nil, err
   }
   key, err := x509.ParsePKCS8PrivateKey(data)
   if err != nil {
      return nil, err
   }
   key1, ok := key.(*ecdsa.PrivateKey)
   if !ok {
      return nil, errors.New("not *ecdsa.PrivateKey")
   }
   return key1, nil
}
