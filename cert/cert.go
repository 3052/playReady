package cert

import (
   "41.neocities.org/playReady/a" // Assuming package 'a' is still external and needed.
   "bytes"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/sha256"
   "encoding/binary"
   "errors"
   "math/big"
   "slices"
)

// Define the types from the original package 'b' within the new package.
// Renamed 'Signature' to 'ecdsaSignature' to avoid conflict and clarify its role.
type ecdsaSignature struct {
   signatureType   uint16
   signatureLength uint16
   SignatureData   []byte // The actual signature bytes
   issuerLength    uint32
   IssuerKey       []byte // The public key of the issuer that signed this
}

// Encode encodes the ecdsaSignature into a byte slice.
func (s *ecdsaSignature) Encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, s.signatureType)
   data = binary.BigEndian.AppendUint16(data, s.signatureLength)
   data = append(data, s.SignatureData...)
   // The original code multiplied issuerLength by 8, implying a bit length,
   // but the IssuerKey length is in bytes. Assuming this multiplication
   // is specific to how it was serialized for a purpose external to this data structure itself.
   data = binary.BigEndian.AppendUint32(data, s.issuerLength*8)
   return append(data, s.IssuerKey...)
}

// New initializes a new ecdsaSignature with provided signature data and signing key.
func (s *ecdsaSignature) New(signatureData, signingKey []byte) {
   s.signatureType = 1
   s.signatureLength = uint16(len(signatureData))
   s.SignatureData = signatureData
   s.issuerLength = uint32(len(signingKey))
   s.IssuerKey = signingKey
}

// Decode decodes a byte slice into the ecdsaSignature structure.
func (s *ecdsaSignature) Decode(data []byte) {
   s.signatureType = binary.BigEndian.Uint16(data)
   data = data[2:]
   s.signatureLength = binary.BigEndian.Uint16(data)
   data = data[2:]
   s.SignatureData = data[:s.signatureLength]
   data = data[s.signatureLength:]
   s.issuerLength = binary.BigEndian.Uint32(data)
   data = data[4:]
   s.IssuerKey = data[:s.issuerLength/8] // Divide by 8 as issuerLength was multiplied by 8 during encode
}

// Constants for object types within the certificate structure.
const (
   objTypeBasic          = 0x0001
   objTypeDomain         = 0x0002
   objTypePc             = 0x0003
   objTypeDevice         = 0x0004
   objTypeFeature        = 0x0005
   objTypeKey            = 0x0006
   objTypeManufacturer   = 0x0007
   objTypeSignature      = 0x0008
   objTypeSilverlight    = 0x0009
   objTypeMetering       = 0x000A
   objTypeExtDataSignKey = 0x000B
   objTypeExtDataContainer = 0x000C
   objTypeExtDataSignature = 0x000D
   objTypeExtDataHwid    = 0x000E
   objTypeServer         = 0x000F
   objTypeSecurityVersion  = 0x0010
   objTypeSecurityVersion2 = 0x0011
)

// LocalDevice represents a device with its certificate chain and keys.
type LocalDevice struct {
   CertificateChain Chain
   EncryptKey       a.EcKey // a.EcKey is from external package 'a'
   SigningKey       a.EcKey // a.EcKey is from external package 'a'
}

// Chain represents a chain of certificates.
type Chain struct {
   magic     [4]byte
   version   uint32
   length    uint32
   flags     uint32
   certCount uint32
   certs     []cert
}

// cert represents a single certificate within a chain.
type cert struct {
   magic           [4]byte
   version         uint32
   length          uint32
   lengthToSignature uint32
   rawData         []byte
   certificateInfo *certInfo
   features        *feature
   keyData         *keyInfo
   manufacturerInfo *manufacturer
   signatureData   *ecdsaSignature // Now uses the renamed type from this package
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
func (c *Chain) CreateLeaf(modelKey, signingKey, encryptKey a.EcKey) error {
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
      signatureData   ecdsaSignature // Use the renamed type
      signatureFtlv   a.FTLV         // a.FTLV is from external package 'a'
      deviceFtlv      a.FTLV
      featureFtlv     a.FTLV
      keyInfoFtlv     a.FTLV
      manufacturerFtlv a.FTLV
      certificateFtlv a.FTLV
   )

   // Calculate digest for the signing key.
   signingKeyDigest := sha256.Sum256(signingKey.PublicBytes())

   // Initialize certificate information.
   certificateInfo.New(
      c.certs[0].certificateInfo.securityLevel, signingKeyDigest[:],
   )
   // Initialize key information for signing and encryption keys.
   builtKeyInfo.New(signingKey.PublicBytes(), encryptKey.PublicBytes())

   // Create FTLV (Fixed Tag Length Value) for certificate info.
   certificateFtlv.New(1, 1, certificateInfo.encode())

   // Create a new device and its FTLV.
   var newDevice device
   newDevice.New()
   deviceFtlv.New(1, 4, newDevice.Encode())

   // Create FTLV for key information.
   keyInfoFtlv.New(1, 6, builtKeyInfo.encode())

   // Create FTLV for manufacturer information, copying from the existing chain's first cert.
   manufacturerFtlv.New(0, 7, c.certs[0].manufacturerInfo.encode())

   // Define feature for the new certificate.
   feature := feature{
      entries: 1,
      features: []uint32{0xD}, // SCALABLE with SL2000, SUPPORTS_PR3_FEATURES
   }
   // Create FTLV for features.
   featureFtlv.New(1, 5, feature.encode())

   // Assemble raw data for the unsigned certificate.
   leaf_data := certificateFtlv.Encode()
   leaf_data = append(leaf_data, deviceFtlv.Encode()...)
   leaf_data = append(leaf_data, featureFtlv.Encode()...)
   leaf_data = append(leaf_data, keyInfoFtlv.Encode()...)
   leaf_data = append(leaf_data, manufacturerFtlv.Encode()...)

   // Create an unsigned certificate object.
   var unsignedCert cert
   unsignedCert.newNoSig(leaf_data)

   // Sign the unsigned certificate's data.
   signatureDigest := sha256.Sum256(unsignedCert.encode())
   r, s, err := ecdsa.Sign(a.Fill('B'), modelKey[0], signatureDigest[:]) // a.Fill is from external package 'a'
   if err != nil {
      return err
   }
   sign := append(r.Bytes(), s.Bytes()...)

   // Initialize the signature data for the new certificate.
   signatureData.New(sign, modelKey.PublicBytes())
   // Create FTLV for the signature.
   signatureFtlv.New(1, 8, signatureData.Encode())

   // Append the signature FTLV to the leaf data.
   leaf_data = append(leaf_data, signatureFtlv.Encode()...)

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

// decode decodes a byte slice into the cert structure.
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
      var ftlv a.FTLV // a.FTLV is from external package 'a'
      j := ftlv.Decode(c.rawData[sum:])

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
         c.signatureData = &ecdsaSignature{} // Use the renamed type
         c.signatureData.Decode(ftlv.Value)

      }

      sum += j
   }

   return n, nil
}

// newNoSig initializes a new cert without signature data.
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

// encode encodes the cert structure into a byte slice.
func (c *cert) encode() []byte {
   data := c.magic[:]
   data = binary.BigEndian.AppendUint32(data, c.version)
   data = binary.BigEndian.AppendUint32(data, c.length)
   data = binary.BigEndian.AppendUint32(data, c.lengthToSignature)
   return append(data, c.rawData[:]...)
}

// feature represents a feature set within a certificate.
type feature struct {
   entries  uint32
   features []uint32
}

// decode decodes a byte slice into the feature structure.
func (f *feature) decode(data []byte) int {
   f.entries = binary.BigEndian.Uint32(data)
   n := 4
   for range f.entries {
      f.features = append(f.features, binary.BigEndian.Uint32(data[n:]))
      n += 4
   }
   return n
}

// New initializes a new feature with a given type.
func (f *feature) New(Type int) {
   f.entries = 1
   f.features = []uint32{uint32(Type)}
}

// encode encodes the feature structure into a byte slice.
func (f *feature) encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, f.entries)

   for i := range f.entries {
      data = binary.BigEndian.AppendUint32(data, f.features[i])
   }

   return data
}

// device represents device capabilities.
type device struct {
   maxLicenseSize       uint32
   maxHeaderSize        uint32
   maxLicenseChainDepth uint32
}

// New initializes default device capabilities.
func (d *device) New() {
   d.maxLicenseSize = 10240
   d.maxHeaderSize = 15360
   d.maxLicenseChainDepth = 2
}

// Encode encodes device capabilities into a byte slice.
func (d *device) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, d.maxLicenseSize)
   data = binary.BigEndian.AppendUint32(data, d.maxHeaderSize)
   return binary.BigEndian.AppendUint32(data, d.maxLicenseChainDepth)
}

// key represents a cryptographic key within keyInfo.
type key struct {
   keyType   uint16
   length    uint16
   flags     uint32
   publicKey [64]byte // ECDSA P256 public key is 64 bytes (X and Y coordinates, 32 bytes each)
   usage     feature  // Features indicating key usage
}

// New initializes a new key with provided data and type.
func (k *key) New(keyData []byte, Type int) {
   k.keyType = 1    // Assuming type 1 is for ECDSA keys
   k.length = 512   // Assuming key length in bits
   copy(k.publicKey[:], keyData)
   k.usage.New(Type)
}

// encode encodes the key structure into a byte slice.
func (k *key) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, k.keyType)
   data = binary.BigEndian.AppendUint16(data, k.length)
   data = binary.BigEndian.AppendUint32(data, k.flags)
   data = append(data, k.publicKey[:]...)
   return append(data, k.usage.encode()...)
}

// decode decodes a byte slice into the key structure.
func (k *key) decode(data []byte) int {
   k.keyType = binary.BigEndian.Uint16(data)
   n := 2
   k.length = binary.BigEndian.Uint16(data[n:])
   n += 2
   k.flags = binary.BigEndian.Uint32(data[n:])
   n += 4
   n += copy(k.publicKey[:], data[n:])
   n += k.usage.decode(data[n:])
   return n
}

// keyInfo represents information about multiple keys.
type keyInfo struct {
   entries uint32
   keys    []key
}

// New initializes a new keyInfo with signing and encryption keys.
func (k *keyInfo) New(signingKey, encryptKey []byte) {
   k.entries = 2
   k.keys = make([]key, 2)
   k.keys[0].New(signingKey, 1) // Type 1 for signing key
   k.keys[1].New(encryptKey, 2) // Type 2 for encryption key
}

// encode encodes the keyInfo structure into a byte slice.
func (k *keyInfo) encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, k.entries)

   for i := range k.entries {
      data = append(data, k.keys[i].encode()...)
   }

   return data
}

// decode decodes a byte slice into the keyInfo structure.
func (k *keyInfo) decode(data []byte) {
   k.entries = binary.BigEndian.Uint32(data)
   data = data[4:]
   for range k.entries {
      var key_data key
      n := key_data.decode(data)
      k.keys = append(k.keys, key_data)
      data = data[n:]
   }
}

// manufacturerInfo contains a length-prefixed string.
type manufacturerInfo struct {
   length uint32
   value  string
}

// encode encodes the manufacturerInfo structure into a byte slice.
func (m *manufacturerInfo) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, m.length)
   return append(data, []byte(m.value)...)
}

// decode decodes a byte slice into the manufacturerInfo structure.
func (m *manufacturerInfo) decode(data []byte) int {
   m.length = binary.BigEndian.Uint32(data)
   n := 4
   // Data is padded to a multiple of 4 bytes.
   padded_length := (m.length + 3) &^ 3
   m.value = string(data[n:][:padded_length])
   n += int(padded_length)
   return n
}

// manufacturer represents manufacturer details.
type manufacturer struct {
   flags          uint32
   manufacturerName manufacturerInfo
   modelName      manufacturerInfo
   modelNumber    manufacturerInfo
}

// encode encodes the manufacturer structure into a byte slice.
func (m *manufacturer) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, m.flags)
   data = append(data, m.manufacturerName.encode()...)
   data = append(data, m.modelName.encode()...)
   return append(data, m.modelNumber.encode()...)
}

// decode decodes a byte slice into the manufacturer structure.
func (m *manufacturer) decode(data []byte) error {
   m.flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   n := m.manufacturerName.decode(data)
   data = data[n:]
   n = m.modelName.decode(data)
   data = data[n:]
   m.modelNumber.decode(data)
   return nil
}

// certInfo contains basic certificate information.
type certInfo struct {
   certificateId [16]byte
   securityLevel uint32
   flags         uint32
   infoType      uint32
   digest        [32]byte
   expiry        uint32
   // NOTE SOME SERVERS, FOR EXAMPLE
   // rakuten.tv
   // WILL LOCK LICENSE TO THE FIRST DEVICE, USING "ClientId" TO DETECT, SO BE
   // CAREFUL USING A VALUE HERE
   clientId [16]byte
}

// encode encodes the certInfo structure into a byte slice.
func (c *certInfo) encode() []byte {
   data := c.certificateId[:]
   data = binary.BigEndian.AppendUint32(data, c.securityLevel)
   data = binary.BigEndian.AppendUint32(data, c.flags)
   data = binary.BigEndian.AppendUint32(data, c.infoType)
   data = append(data, c.digest[:]...)
   data = binary.BigEndian.AppendUint32(data, c.expiry)
   return append(data, c.clientId[:]...)
}

// New initializes a new certInfo with security level and digest.
func (c *certInfo) New(securityLevel uint32, digest []byte) {
   c.securityLevel = securityLevel
   c.infoType = 2 // Assuming infoType 2 is a standard type
   copy(c.digest[:], digest)
   c.expiry = 4294967295 // Max uint32, effectively never expires
}

// decode decodes a byte slice into the certInfo structure.
func (c *certInfo) decode(data []byte) {
   n := copy(c.certificateId[:], data)
   data = data[n:]
   c.securityLevel = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.infoType = binary.BigEndian.Uint32(data)
   data = data[4:]
   n = copy(c.digest[:], data)
   data = data[n:]
   c.expiry = binary.BigEndian.Uint32(data)
   data = data[4:]
   copy(c.clientId[:], data)
}
