package playReady

import (
   "41.neocities.org/playReady/xml"
   "bytes"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/sha256"
   "encoding/hex"
   "errors"
   "math/big"
   "slices"
)

type Fill byte

func (f Fill) Read(data []byte) (int, error) {
   for index := range data {
      data[index] = byte(f)
   }
   return len(data), nil
}

type xmlKey struct {
   PublicKey ecdsa.PublicKey
   X         [32]byte
}

func (x *xmlKey) New() {
   x.PublicKey.X, x.PublicKey.Y = elliptic.P256().ScalarBaseMult([]byte{1})
   x.PublicKey.X.FillBytes(x.X[:])
}

func (x *xmlKey) aesIv() []byte {
   return x.X[:16]
}

func (x *xmlKey) aesKey() []byte {
   return x.X[16:]
}

// Private returns the private key bytes.
func (e EcKey) Private() []byte {
   return e[0].D.Bytes()
}

// PublicBytes returns the public key bytes.
func (e *EcKey) public() []byte {
   return append(e[0].PublicKey.X.Bytes(), e[0].PublicKey.Y.Bytes()...)
}

func sign(key *ecdsa.PrivateKey, hash []byte) ([]byte, error) {
   r, s, err := ecdsa.Sign(Fill('A'), key, hash)
   if err != nil {
      return nil, err
   }
   return append(r.Bytes(), s.Bytes()...), nil
}

func (e *EcKey) Decode(data []byte) {
   var public ecdsa.PublicKey
   public.Curve = elliptic.P256()
   public.X, public.Y = public.Curve.ScalarBaseMult(data)
   e[0].D = new(big.Int).SetBytes(data)
   e[0].PublicKey = public
}

type EcKey [1]ecdsa.PrivateKey

///

// they downgrade certs from the cert digest (hash of the signing key)
func (f Fill) Key() *EcKey {
   var data [32]byte
   f.Read(data[:])
   var key EcKey
   key.Decode(data[:])
   return &key
}

func (c *Certificate) verify(pubKey []byte) bool {
   if !bytes.Equal(c.Signature.IssuerKey, pubKey) {
      return false
   }
   // Reconstruct the ECDSA public key from the byte slice.
   publicKey := ecdsa.PublicKey{
      Curve: elliptic.P256(), // Assuming P256 curve
      X:     new(big.Int).SetBytes(pubKey[:32]),
      Y:     new(big.Int).SetBytes(pubKey[32:]),
   }
   data := c.Append(nil)
   data = data[:c.LengthToSignature]
   signatureDigest := sha256.Sum256(data)
   signature := c.Signature.Signature
   r := new(big.Int).SetBytes(signature[:32])
   s := new(big.Int).SetBytes(signature[32:])
   return ecdsa.Verify(&publicKey, signatureDigest[:], r, s)
}

func elGamalKeyGeneration() *ecdsa.PublicKey {
   data, _ := hex.DecodeString(wmrmPublicKey)
   var key ecdsa.PublicKey
   key.X = new(big.Int).SetBytes(data[:32])
   key.Y = new(big.Int).SetBytes(data[32:])
   return &key
}

func elGamalEncrypt(data, key *ecdsa.PublicKey) []byte {
   g := elliptic.P256()
   y := big.NewInt(1) // In a real scenario, y should be truly random
   c1x, c1y := g.ScalarBaseMult(y.Bytes())
   sX, sY := g.ScalarMult(key.X, key.Y, y.Bytes())
   c2X, c2Y := g.Add(data.X, data.Y, sX, sY)
   return slices.Concat(
      c1x.Bytes(), c1y.Bytes(),
      c2X.Bytes(), c2Y.Bytes(),
   )
}

func elGamalDecrypt(data []byte, key *ecdsa.PrivateKey) (*big.Int, *big.Int) {
   curve := elliptic.P256()
   // Unmarshal C1 component
   c1X := new(big.Int).SetBytes(data[:32])
   c1Y := new(big.Int).SetBytes(data[32:64])
   // Unmarshal C2 component
   c2X := new(big.Int).SetBytes(data[64:96])
   c2Y := new(big.Int).SetBytes(data[96:])
   // Calculate shared secret s = C1^x
   sX, sY := curve.ScalarMult(c1X, c1Y, key.D.Bytes())
   // Invert the point for subtraction
   sY.Neg(sY)
   sY.Mod(sY, curve.Params().P)
   // Recover message point: M = C2 - s
   return curve.Add(c2X, c2Y, sX, sY)
}

func (c *ContentKey) decrypt(key *ecdsa.PrivateKey, aux *AuxKeys) error {
   switch c.CipherType {
   case 3:
      messageX, _ := elGamalDecrypt(c.Value, key)
      c.Value = messageX.Bytes()
      return nil
   case 6:
      return c.scalable(key, aux)
   }
   return errors.New("cannot decrypt key")
}

func (c *ContentKey) scalable(key *ecdsa.PrivateKey, aux *AuxKeys) error {
   rootKeyInfo, leafKeys := c.Value[:144], c.Value[144:]
   rootKey := rootKeyInfo[128:]
   messageX, _ := elGamalDecrypt(rootKeyInfo[:128], key)
   decrypted := messageX.Bytes()
   var (
      ci [16]byte
      ck [16]byte
   )
   for i := range 16 {
      ci[i] = decrypted[i*2]
      ck[i] = decrypted[i*2+1]
   }
   constantZero, err := hex.DecodeString(magicConstantZero)
   if err != nil {
      return err
   }
   rgbUplinkXkey := xorKey(ck[:], constantZero)
   contentKeyPrime, err := aesEcbEncrypt(rgbUplinkXkey, ck[:])
   if err != nil {
      return err
   }
   auxKeyCalc, err := aesEcbEncrypt(aux.Keys[0].Key[:], contentKeyPrime)
   if err != nil {
      return err
   }
   oSecondaryKey, err := aesEcbEncrypt(rootKey, ck[:])
   if err != nil {
      return err
   }
   c.Value, err = aesEcbEncrypt(leafKeys, auxKeyCalc)
   if err != nil {
      return err
   }
   c.Value, err = aesEcbEncrypt(c.Value, oSecondaryKey)
   if err != nil {
      return err
   }
   return nil
}

func newLa(m *ecdsa.PublicKey, cipherData, kid []byte) *xml.La {
   return &xml.La{
      XmlNs:   "http://schemas.microsoft.com/DRM/2007/03/protocols",
      Id:      "SignedData",
      Version: "1",
      ContentHeader: xml.ContentHeader{
         WrmHeader: xml.WrmHeader{
            XmlNs:   "http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader",
            Version: "4.0.0.0",
            Data: xml.WrmHeaderData{
               ProtectInfo: xml.ProtectInfo{
                  KeyLen: "16",
                  AlgId:  "AESCTR",
               },
               Kid: kid,
            },
         },
      },
      EncryptedData: xml.EncryptedData{
         XmlNs: "http://www.w3.org/2001/04/xmlenc#",
         Type:  "http://www.w3.org/2001/04/xmlenc#Element",
         EncryptionMethod: xml.Algorithm{
            Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
         },
         KeyInfo: xml.KeyInfo{
            XmlNs: "http://www.w3.org/2000/09/xmldsig#",
            EncryptedKey: xml.EncryptedKey{
               XmlNs: "http://www.w3.org/2001/04/xmlenc#",
               EncryptionMethod: xml.Algorithm{
                  Algorithm: "http://schemas.microsoft.com/DRM/2007/03/protocols#ecc256",
               },
               KeyInfo: xml.EncryptedKeyInfo{
                  XmlNs:   "http://www.w3.org/2000/09/xmldsig#",
                  KeyName: "WMRMServer",
               },
               CipherData: xml.CipherData{
                  CipherValue: elGamalEncrypt(m, elGamalKeyGeneration()),
               },
            },
         },
         CipherData: xml.CipherData{
            CipherValue: cipherData,
         },
      },
   }
}
