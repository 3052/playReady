package playReady

import (
   "41.neocities.org/playReady/xml"
   "bytes"
   "crypto/ecdsa"
   "crypto/sha256"
   "encoding/base64"
   "encoding/binary"
   "errors"
   "slices"
)

// Chain represents a chain of certificates.
type Chain struct {
   magic     [4]byte
   version   uint32
   length    uint32
   flags     uint32
   certCount uint32
   certs     []cert
}

// Encode encodes the Chain into a byte slice.
func (c *Chain) Encode() []byte {
   data := c.magic[:]
   data = binary.BigEndian.AppendUint32(data, c.version)
   data = binary.BigEndian.AppendUint32(data, c.length)
   data = binary.BigEndian.AppendUint32(data, c.flags)
   data = binary.BigEndian.AppendUint32(data, c.certCount)
   for _, cert1 := range c.certs {
      data = append(data, cert1.encode()...)
   }
   return data
}

// verify verifies the entire certificate chain.
func (c *Chain) verify() bool {
   // Start verification with the issuer key of the last certificate in the chain.
   modelBase := c.certs[len(c.certs)-1].signatureData.IssuerKey
   for i := len(c.certs) - 1; i >= 0; i-- {
      // Verify each certificate using the public key of its issuer.
      valid := c.certs[i].verify(modelBase[:])
      if !valid {
         return false
      }
      // The public key of the current certificate becomes the issuer key for the next in the chain.
      modelBase = c.certs[i].keyData.keys[0].publicKey[:]
   }
   return true
}

// CreateLeaf creates a new leaf certificate and adds it to the chain.
func (c *Chain) CreateLeaf(modelKey, signingKey, encryptKey EcKey) error {
   // Verify that the provided modelKey matches the public key in the chain's first certificate.
   if !bytes.Equal(
      c.certs[0].keyData.keys[0].publicKey[:], modelKey.PublicBytes(),
   ) {
      return errors.New("zgpriv not for cert")
   }
   // Verify the existing chain's validity.
   if !c.verify() {
      return errors.New("cert is not valid")
   }

   var (
      builtKeyInfo    keyInfo
      certificateInfo certInfo
      signatureData   ecdsaSignature
      signatureFtlv   ftlv
      deviceFtlv      ftlv
      featureFtlv     ftlv
      keyInfoFtlv     ftlv
      manufacturerFtlv ftlv
      certificateFtlv ftlv
   )

   // Calculate digest for the signing key.
   signingKeyDigest := sha256.Sum256(signingKey.PublicBytes())

   // Initialize certificate information.
   certificateInfo.new(
      c.certs[0].certificateInfo.securityLevel, signingKeyDigest[:],
   )
   // Initialize key information for signing and encryption keys.
   builtKeyInfo.new(signingKey.PublicBytes(), encryptKey.PublicBytes())

   // Create FTLV (Fixed Tag Length Value) for certificate info.
   certificateFtlv.new(1, 1, certificateInfo.encode())

   // Create a new device and its FTLV.
   var newDevice device
   newDevice.new()
   deviceFtlv.new(1, 4, newDevice.encode())

   // Create FTLV for key information.
   keyInfoFtlv.new(1, 6, builtKeyInfo.encode())

   // Create FTLV for manufacturer information, copying from the existing chain's first cert.
   manufacturerFtlv.new(0, 7, c.certs[0].manufacturerInfo.encode())

   // Define feature for the new certificate.
   feature := feature{
      entries:  1,
      features: []uint32{0xD}, // SCALABLE with SL2000, SUPPORTS_PR3_FEATURES
   }
   // Create FTLV for features.
   featureFtlv.new(1, 5, feature.encode())

   // Assemble raw data for the unsigned certificate.
   leaf_data := certificateFtlv.encode()
   leaf_data = append(leaf_data, deviceFtlv.encode()...)
   leaf_data = append(leaf_data, featureFtlv.encode()...)
   leaf_data = append(leaf_data, keyInfoFtlv.encode()...)
   leaf_data = append(leaf_data, manufacturerFtlv.encode()...)

   // Create an unsigned certificate object.
   var unsignedCert cert
   unsignedCert.newNoSig(leaf_data)

   // Sign the unsigned certificate's data.
   signatureDigest := sha256.Sum256(unsignedCert.encode())
   r, s, err := ecdsa.Sign(Fill('B'), modelKey[0], signatureDigest[:])
   if err != nil {
      return err
   }
   sign := append(r.Bytes(), s.Bytes()...)

   // Initialize the signature data for the new certificate.
   signatureData.new(sign, modelKey.PublicBytes())
   // Create FTLV for the signature.
   signatureFtlv.new(1, 8, signatureData.encode())

   // Append the signature FTLV to the leaf data.
   leaf_data = append(leaf_data, signatureFtlv.encode()...)

   // Update the unsigned certificate's length and rawData.
   unsignedCert.length = uint32(len(leaf_data)) + 16
   unsignedCert.rawData = leaf_data

   // Update the chain's length, certificate count, and insert the new certificate.
   c.length += unsignedCert.length
   c.certCount += 1
   c.certs = slices.Insert(c.certs, 0, unsignedCert)
   return nil
}

// Decode decodes a byte slice into the Chain structure.
func (c *Chain) Decode(data []byte) error {
   n := copy(c.magic[:], data)
   if string(c.magic[:]) != "CHAI" {
      return errors.New("failed to find chain magic")
   }
   data = data[n:]
   c.version = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.length = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.certCount = binary.BigEndian.Uint32(data)
   data = data[4:]

   for range c.certCount {
      var cert1 cert
      i, err := cert1.decode(data)
      if err != nil {
         return err
      }
      data = data[i:]
      c.certs = append(c.certs, cert1)
   }
   return nil
}

// getCipherData prepares cipher data for the license acquisition challenge.
func getCipherData(chain *Chain, key *xmlKey) ([]byte, error) {
   value := xml.Data{
      CertificateChains: xml.CertificateChains{
         CertificateChain: base64.StdEncoding.EncodeToString(chain.Encode()),
      },
      Features: xml.Features{
         Feature: xml.Feature{"AESCBC"}, // SCALABLE
      },
   }
   data1, err := value.Marshal()
   if err != nil {
      return nil, err
   }
   data1, err = aesCBCHandler(data1, key.aesKey(), key.aesIv(), true)
   if err != nil {
      return nil, err
   }
   return append(key.aesIv(), data1...), nil
}
