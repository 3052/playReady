package playReady

import (
   "41.neocities.org/playReady/xml"
   "bytes"
   "crypto/aes"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/sha256"
   "encoding/base64"
   "encoding/binary"
   "errors"
   "github.com/deatil/go-cryptobin/mac"
   "math/big"
   "slices"
)

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
      builtKeyInfo     keyInfo
      certificateInfo  certInfo
      signatureData    ecdsaSignature
      signatureFtlv    ftlv
      deviceFtlv       ftlv
      featureFtlv      ftlv
      keyInfoFtlv      ftlv
      manufacturerFtlv ftlv
      certificateFtlv  ftlv
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
   deviceFtlv.New(1, 4, newDevice.encode())

   // Create FTLV for key information.
   keyInfoFtlv.New(1, 6, builtKeyInfo.encode())

   // Create FTLV for manufacturer information, copying from the existing chain's first cert.
   manufacturerFtlv.New(0, 7, c.certs[0].manufacturerInfo.encode())

   // Define feature for the new certificate.
   feature := feature{
      entries:  1,
      features: []uint32{0xD}, // SCALABLE with SL2000, SUPPORTS_PR3_FEATURES
   }
   // Create FTLV for features.
   featureFtlv.New(1, 5, feature.encode())

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
   signatureData.New(sign, modelKey.PublicBytes())
   // Create FTLV for the signature.
   signatureFtlv.New(1, 8, signatureData.encode())

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

// ParseLicense parses a SOAP response containing a PlayReady license.
func ParseLicense(device *LocalDevice, data []byte) (*ContentKey, error) {
   var response xml.EnvelopeResponse
   err := response.Unmarshal(data)
   if err != nil {
      return nil, err
   }
   if fault := response.Body.Fault; fault != nil {
      return nil, errors.New(fault.Fault)
   }
   decoded, err := base64.StdEncoding.DecodeString(response.
      Body.
      AcquireLicenseResponse.
      AcquireLicenseResult.
      Response.
      LicenseResponse.
      Licenses.
      License,
   )
   if err != nil {
      return nil, err
   }
   var license licenseResponse
   err = license.decode(decoded)
   if err != nil {
      return nil, err
   }
   if !bytes.Equal(license.eccKeyObject.Value, device.EncryptKey.PublicBytes()) {
      return nil, errors.New("license response is not for this device")
   }
   err = license.contentKeyObject.decrypt(
      device.EncryptKey[0], license.auxKeyObject,
   )
   if err != nil {
      return nil, err
   }
   err = license.verify(license.contentKeyObject.Integrity.GUID())
   if err != nil {
      return nil, err
   }
   return license.contentKeyObject, nil
}

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
         c.manufacturerInfo.decode(ftlv.Value)

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

// certInfo contains basic certificate information. Renamed to avoid conflict.
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

// new initializes a new certInfo with security level and digest.
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

// Encode encodes a LicenseResponse into a byte slice.
func (l *licenseResponse) encode() []byte {
   data := l.Magic[:]
   data = binary.BigEndian.AppendUint16(data, l.Offset)
   data = binary.BigEndian.AppendUint16(data, l.Version)
   data = append(data, l.RightsID[:]...)
   return append(data, l.OuterContainer.encode()...)
}

// Decode decodes a byte slice into a LicenseResponse structure.
func (l *licenseResponse) decode(data []byte) error {
   l.RawData = data
   n := copy(l.Magic[:], data)
   l.Offset = binary.BigEndian.Uint16(data[n:])
   n += 2
   l.Version = binary.BigEndian.Uint16(data[n:])
   n += 2
   n += copy(l.RightsID[:], data[n:])
   n += l.OuterContainer.decode(data[n:])

   var size int

   for size < int(l.OuterContainer.Length)-16 {
      var value ftlv
      i := value.decode(l.OuterContainer.Value[size:])
      switch xmrType(value.Type) {
      case globalPolicyContainerEntryType: // 2
         // Rakuten
      case playbackPolicyContainerEntryType: // 4
         // Rakuten
      case keyMaterialContainerEntryType: // 9
         var j int
         for j < int(value.Length)-16 {
            var value1 ftlv
            k := value1.decode(value.Value[j:])

            switch xmrType(value1.Type) {
            case contentKeyEntryType: // 10
               l.contentKeyObject = &ContentKey{}
               l.contentKeyObject.decode(value1.Value)

            case deviceKeyEntryType: // 42
               l.eccKeyObject = &eccKey{}
               l.eccKeyObject.decode(value1.Value)

            case auxKeyEntryType: // 81
               l.auxKeyObject = &auxKeys{}
               l.auxKeyObject.decode(value1.Value)

            default:
               return errors.New("FTLV.type")
            }
            j += k
         }
      case signatureEntryType: // 11
         l.signatureObject = &signature{}
         l.signatureObject.decode(value.Value)
         l.signatureObject.Length = uint16(value.Length)

      default:
         return errors.New("FTLV.type")
      }
      size += i
   }

   return nil
}

// Verify verifies the license response signature.
func (l *licenseResponse) verify(contentIntegrity []byte) error {
   data := l.encode()
   data = data[:len(l.RawData)-int(l.signatureObject.Length)]
   block, err := aes.NewCipher(contentIntegrity)
   if err != nil {
      return err
   }
   data = mac.NewCMAC(block, aes.BlockSize).MAC(data)
   if !bytes.Equal(data, l.signatureObject.Data) {
      return errors.New("failed to decrypt the keys")
   }
   return nil
}

type licenseResponse struct {
   RawData          []byte
   Magic            [4]byte
   Offset           uint16
   Version          uint16
   RightsID         [16]byte
   OuterContainer   ftlv
   contentKeyObject *ContentKey
   eccKeyObject     *eccKey
   signatureObject  *signature
   auxKeyObject     *auxKeys
}
