package c

import (
   "41.neocities.org/playReady/a"
   "41.neocities.org/playReady/b"
   "bytes"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/sha256"
   "encoding/binary"
   "errors"
   "math/big"
   "slices"
)

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
      var ftlv a.FTLV
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
         c.signatureData = &b.Signature{} // b.Signature is a public type from package b
         // We cannot change the imported package's public types, so b.Signature remains as is.
         // However, if we were to define it in this package, it would be 'signature'.
         c.signatureData.Decode(ftlv.Value)

      }

      sum += j
   }

   return n, nil
}

type LocalDevice struct {
   CertificateChain Chain
   EncryptKey       a.EcKey
   SigningKey       a.EcKey
}

type Chain struct {
   magic     [4]byte
   version   uint32
   length    uint32
   flags     uint32
   certCount uint32
   certs     []cert
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
   signatureData     *b.Signature // See comment above regarding b.Signature
}

func (c *cert) newNoSig(data []byte) {
   copy(c.magic[:], "CERT")
   c.version = 1
   c.length = uint32(len(data)) + 16 + 144
   c.lengthToSignature = uint32(len(data)) + 16
   c.rawData = data
}

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

func (c *Chain) verify() bool {
   // Assuming SignatureData and IssuerKey from package b are public as per the original code.
   modelBase := c.certs[len(c.certs)-1].signatureData.IssuerKey
   for i := len(c.certs) - 1; i >= 0; i-- {
      valid := c.certs[i].verify(modelBase[:])
      if !valid {
         return false
      }
      modelBase = c.certs[i].keyData.keys[0].publicKey[:]
   }
   return true
}

func (c *cert) verify(pubKey []byte) bool {
   // Assuming SignatureData and IssuerKey from package b are public as per the original code.
   if !bytes.Equal(c.signatureData.IssuerKey, pubKey) {
      return false
   }
   data := c.encode()
   data = data[:c.lengthToSignature]
   x := new(big.Int).SetBytes(pubKey[:32])
   y := new(big.Int).SetBytes(pubKey[32:])
   publicKey := &ecdsa.PublicKey{
      Curve: elliptic.P256(),
      X:     x,
      Y:     y,
   }
   sig := c.signatureData.SignatureData // b.Signature.SignatureData
   signatureDigest := sha256.Sum256(data)
   r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
   return ecdsa.Verify(publicKey, signatureDigest[:], r, s)
}
func (c *cert) encode() []byte {
   data := c.magic[:]
   data = binary.BigEndian.AppendUint32(data, c.version)
   data = binary.BigEndian.AppendUint32(data, c.length)
   data = binary.BigEndian.AppendUint32(data, c.lengthToSignature)
   return append(data, c.rawData[:]...)
}

func (f *feature) decode(data []byte) int {
   f.entries = binary.BigEndian.Uint32(data)
   n := 4
   for range f.entries {
      f.features = append(f.features, binary.BigEndian.Uint32(data[n:]))
      n += 4
   }
   return n
}

type device struct {
   maxLicenseSize       uint32
   maxHeaderSize        uint32
   maxLicenseChainDepth uint32
}

func (d *device) New() {
   d.maxLicenseSize = 10240
   d.maxHeaderSize = 15360
   d.maxLicenseChainDepth = 2
}

func (d *device) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, d.maxLicenseSize)
   data = binary.BigEndian.AppendUint32(data, d.maxHeaderSize)
   return binary.BigEndian.AppendUint32(data, d.maxLicenseChainDepth)
}

func (c *Chain) CreateLeaf(modelKey, signingKey, encryptKey a.EcKey) error {
   if !bytes.Equal(
      c.certs[0].keyData.keys[0].publicKey[:], modelKey.PublicBytes(),
   ) {
      return errors.New("zgpriv not for cert")
   }
   if !c.verify() {
      return errors.New("cert is not valid")
   }
   var (
      builtKeyInfo     keyInfo
      certificateInfo  certInfo
      signatureData    b.Signature // See comment above regarding b.Signature
      signatureFtlv    a.FTLV
      deviceFtlv       a.FTLV
      featureFtlv      a.FTLV
      keyInfoFtlv      a.FTLV
      manufacturerFtlv a.FTLV
      certificateFtlv  a.FTLV
   )
   signingKeyDigest := sha256.Sum256(signingKey.PublicBytes())
   certificateInfo.New(
      c.certs[0].certificateInfo.securityLevel, signingKeyDigest[:],
   )
   builtKeyInfo.New(signingKey.PublicBytes(), encryptKey.PublicBytes())
   certificateFtlv.New(1, 1, certificateInfo.encode()) // a.FTLV.New remains public
   var newDevice device
   newDevice.New()
   keyInfoFtlv.New(1, 6, builtKeyInfo.encode())                     // a.FTLV.New remains public
   manufacturerFtlv.New(0, 7, c.certs[0].manufacturerInfo.encode()) // a.FTLV.New remains public
   feature := feature{
      entries: 1,
      // SCALABLE with SL2000
      // SUPPORTS_PR3_FEATURES
      features: []uint32{0xD},
   }
   featureFtlv.New(1, 5, feature.encode())  // a.FTLV.New remains public
   deviceFtlv.New(1, 4, newDevice.Encode()) // a.FTLV.New remains public
   leaf_data := certificateFtlv.Encode()    // a.FTLV.Encode remains public
   leaf_data = append(leaf_data, deviceFtlv.Encode()...)
   leaf_data = append(leaf_data, featureFtlv.Encode()...)
   leaf_data = append(leaf_data, keyInfoFtlv.Encode()...)
   leaf_data = append(leaf_data, manufacturerFtlv.Encode()...)
   var unsignedCert cert
   unsignedCert.newNoSig(leaf_data)
   signatureDigest := sha256.Sum256(unsignedCert.encode())
   r, s, err := ecdsa.Sign(a.Fill('B'), modelKey[0], signatureDigest[:]) // a.Fill remains public
   if err != nil {
      return err
   }
   sign := append(r.Bytes(), s.Bytes()...)
   // b.Signature.New remains public as per the original structure.
   signatureData.New(sign, modelKey.PublicBytes())
   signatureFtlv.New(1, 8, signatureData.Encode()) // a.FTLV.New and b.Signature.Encode remain public
   leaf_data = append(leaf_data, signatureFtlv.Encode()...)
   unsignedCert.length = uint32(len(leaf_data)) + 16
   unsignedCert.rawData = leaf_data
   c.length += unsignedCert.length
   c.certCount += 1
   c.certs = slices.Insert(c.certs, 0, unsignedCert)
   return nil
}

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

type feature struct {
   entries  uint32
   features []uint32
}

func (f *feature) New(Type int) {
   f.entries = 1
   f.features = []uint32{uint32(Type)}
}

func (f *feature) encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, f.entries)

   for i := range f.entries {
      data = binary.BigEndian.AppendUint32(data, f.features[i])
   }

   return data
}

func (k *key) New(keyData []byte, Type int) {
   k.keyType = 1
   k.length = 512
   copy(k.publicKey[:], keyData)
   k.usage.New(Type)
}

func (k *key) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, k.keyType)
   data = binary.BigEndian.AppendUint16(data, k.length)
   data = binary.BigEndian.AppendUint32(data, k.flags)
   data = append(data, k.publicKey[:]...)
   return append(data, k.usage.encode()...)
}

func (k *keyInfo) New(signingKey, encryptKey []byte) {
   k.entries = 2
   k.keys = make([]key, 2)
   k.keys[0].New(signingKey, 1)
   k.keys[1].New(encryptKey, 2)
}

type keyInfo struct {
   entries uint32
   keys    []key
}

func (k *keyInfo) encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, k.entries)

   for i := range k.entries {
      data = append(data, k.keys[i].encode()...)
   }

   return data
}

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

type manufacturerInfo struct {
   length uint32
   value  string
}

func (m *manufacturerInfo) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, m.length)
   return append(data, []byte(m.value)...)
}

func (m *manufacturerInfo) decode(data []byte) int {
   m.length = binary.BigEndian.Uint32(data)
   n := 4
   padded_length := (m.length + 3) &^ 3
   m.value = string(data[n:][:padded_length])
   n += int(padded_length)
   return n
}

type manufacturer struct {
   flags            uint32
   manufacturerName manufacturerInfo
   modelName        manufacturerInfo
   modelNumber      manufacturerInfo
}

func (m *manufacturer) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, m.flags)
   data = append(data, m.manufacturerName.encode()...)
   data = append(data, m.modelName.encode()...)
   return append(data, m.modelNumber.encode()...)
}

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

func (c *certInfo) encode() []byte {
   data := c.certificateId[:]
   data = binary.BigEndian.AppendUint32(data, c.securityLevel)
   data = binary.BigEndian.AppendUint32(data, c.flags)
   data = binary.BigEndian.AppendUint32(data, c.infoType)
   data = append(data, c.digest[:]...)
   data = binary.BigEndian.AppendUint32(data, c.expiry)
   return append(data, c.clientId[:]...)
}

const (
   objTypeBasic            = 0x0001
   objTypeDomain           = 0x0002
   objTypePc               = 0x0003
   objTypeDevice           = 0x0004
   objTypeFeature          = 0x0005
   objTypeKey              = 0x0006
   objTypeManufacturer     = 0x0007
   objTypeSignature        = 0x0008
   objTypeSilverlight      = 0x0009
   objTypeMetering         = 0x000A
   objTypeExtDataSignKey   = 0x000B
   objTypeExtDataContainer = 0x000C
   objTypeExtDataSignature = 0x000D
   objTypeExtDataHwid      = 0x000E
   objTypeServer           = 0x000F
   objTypeSecurityVersion  = 0x0010
   objTypeSecurityVersion2 = 0x0011
)

func (c *certInfo) New(securityLevel uint32, digest []byte) {
   c.securityLevel = securityLevel
   c.infoType = 2
   copy(c.digest[:], digest)
   c.expiry = 4294967295
}

type key struct {
   keyType   uint16
   length    uint16
   flags     uint32
   publicKey [64]byte
   usage     feature
}

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
