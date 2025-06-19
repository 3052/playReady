package playReady

import (
   "bytes"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/sha256"
   "encoding/binary"
   "errors"
   "math/big"
)

func (c *Certificate) verify(pubKey []byte) bool {
   if !bytes.Equal(c.signature.IssuerKey, pubKey) {
      return false
   }
   // Reconstruct the ECDSA public key from the byte slice.
   publicKey := ecdsa.PublicKey{
      Curve: elliptic.P256(), // Assuming P256 curve
      X:     new(big.Int).SetBytes(pubKey[:32]),
      Y:     new(big.Int).SetBytes(pubKey[32:]),
   }
   data := c.encode()
   data = data[:c.LengthToSignature]
   signatureDigest := sha256.Sum256(data)
   signature := c.signature.SignatureData
   r := new(big.Int).SetBytes(signature[:32])
   s := new(big.Int).SetBytes(signature[32:])
   return ecdsa.Verify(&publicKey, signatureDigest[:], r, s)
}

type Certificate struct {
   Magic             [4]byte
   Version           uint32
   Length            uint32
   LengthToSignature uint32
   rawData           []byte
   certificateInfo   *certificateInfo
   features          *features
   keyInfo           *keyInfo
   manufacturerInfo  *manufacturer
   signature         *certificateSignature
}

func (c *Certificate) newNoSig(data []byte) {
   copy(c.Magic[:], "CERT")
   c.Version = 1
   // length = length of raw data + header size (16) + signature size (144)
   c.Length = uint32(len(data)) + 16 + 144
   // lengthToSignature = length of raw data + header size (16)
   c.LengthToSignature = uint32(len(data)) + 16
   c.rawData = data
}

func (c *Certificate) decode(data []byte) (int, error) {
   n := copy(c.Magic[:], data)
   if string(c.Magic[:]) != "CERT" {
      return 0, errors.New("failed to find cert magic")
   }
   c.Version = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.Length = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.LengthToSignature = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.rawData = data[n:][:c.Length-16]
   n += len(c.rawData)
   var n1 int
   for n1 < len(c.rawData) {
      var value ftlv
      n1 += value.decode(c.rawData[n1:])
      switch value.Type {
      case objTypeBasic:
         c.certificateInfo = &certificateInfo{}
         c.certificateInfo.decode(value.Value)
      case objTypeFeature:
         c.features = &features{}
         c.features.decode(value.Value)
      case objTypeKey:
         c.keyInfo = &keyInfo{}
         c.keyInfo.decode(value.Value)
      case objTypeManufacturer:
         c.manufacturerInfo = &manufacturer{}
         c.manufacturerInfo.decode(value.Value)
      case objTypeSignature:
         c.signature = &certificateSignature{}
         c.signature.decode(value.Value)
      }
   }
   return n, nil
}

// encode encodes the Cert structure into a byte slice.
func (c *Certificate) encode() []byte {
   data := c.Magic[:]
   data = binary.BigEndian.AppendUint32(data, c.Version)
   data = binary.BigEndian.AppendUint32(data, c.Length)
   data = binary.BigEndian.AppendUint32(data, c.LengthToSignature)
   return append(data, c.rawData...)
}
