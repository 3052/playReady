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

type cert struct {
   magic             [4]byte
   version           uint32
   length            uint32
   lengthToSignature uint32
   rawData           []byte
   certificateInfo   *certInfo
   features          *feature
   keyData           *keyInfo
   manufacturerInfo  *manufacturer
   signatureData     *ecdsaSignature
}

// decode decodes a byte slice into the Cert structure.
func (c *cert) decode(data []byte) (int, error) {
   n := copy(c.magic[:], data)

   if string(c.magic[:]) != "CERT" {
      return 0, errors.New("failed to find cert magic")
   }

   c.version = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.length = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.lengthToSignature = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.rawData = data[n:][:c.length-16]
   n += len(c.rawData)

   var sum int
   for sum < int(c.length)-16 {
      var ftlv ftlv
      j := ftlv.decode(c.rawData[sum:])

      switch ftlv.Type {
      case objTypeBasic:
         c.certificateInfo = &certInfo{}
         c.certificateInfo.decode(ftlv.Value)

      case objTypeFeature:
         c.features = &feature{}
         c.features.decode(ftlv.Value)

      case objTypeKey:
         c.keyData = &keyInfo{}
         c.keyData.decode(ftlv.Value)

      case objTypeManufacturer:
         c.manufacturerInfo = &manufacturer{}
         err := c.manufacturerInfo.decode(ftlv.Value)
         if err != nil {
            return 0, err
         }

      case objTypeSignature:
         c.signatureData = &ecdsaSignature{}
         c.signatureData.decode(ftlv.Value)

      }

      sum += j
   }

   return n, nil
}

// newNoSig initializes a new Cert without signature data.
func (c *cert) newNoSig(data []byte) {
   copy(c.magic[:], "CERT")
   c.version = 1
   // length = length of raw data + header size (16) + signature size (144)
   c.length = uint32(len(data)) + 16 + 144
   // lengthToSignature = length of raw data + header size (16)
   c.lengthToSignature = uint32(len(data)) + 16
   c.rawData = data
}

// verify verifies the signature of the certificate using the provided public key.
func (c *cert) verify(pubKey []byte) bool {
   // Check if the issuer key in the signature matches the provided public key.
   if !bytes.Equal(c.signatureData.IssuerKey, pubKey) {
      return false
   }
   // Get the data that was signed (up to lengthToSignature).
   data := c.encode()
   data = data[:c.lengthToSignature]

   // Reconstruct the ECDSA public key from the byte slice.
   x := new(big.Int).SetBytes(pubKey[:32])
   y := new(big.Int).SetBytes(pubKey[32:])
   publicKey := &ecdsa.PublicKey{
      Curve: elliptic.P256(), // Assuming P256 curve
      X:     x,
      Y:     y,
   }

   // Extract R and S components from the signature data.
   sig := c.signatureData.SignatureData
   signatureDigest := sha256.Sum256(data)
   r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])

   // Verify the signature.
   return ecdsa.Verify(publicKey, signatureDigest[:], r, s)
}

// encode encodes the Cert structure into a byte slice.
func (c *cert) encode() []byte {
   data := c.magic[:]
   data = binary.BigEndian.AppendUint32(data, c.version)
   data = binary.BigEndian.AppendUint32(data, c.length)
   data = binary.BigEndian.AppendUint32(data, c.lengthToSignature)
   return append(data, c.rawData[:]...)
}
