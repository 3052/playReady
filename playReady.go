package playReady

import (
   "bytes"
   "crypto/aes"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/sha256"
   "encoding/base64"
   "encoding/binary"
   "encoding/hex"
   "errors"
   "math/big"
   "slices"

   "github.com/deatil/go-cryptobin/cryptobin/crypto"
   "github.com/deatil/go-cryptobin/mac"

   "41.neocities.org/playReady/xml" // Assuming xml package remains separate
)

// WMRM_PUBLIC_KEY is the Windows Media DRM public key used in ElGamal encryption.
const WMRM_PUBLIC_KEY = "C8B6AF16EE941AADAA5389B4AF2C10E356BE42AF175EF3FACE93254E7B0B3D9B982B27B5CB2341326E56AA857DBFD5C634CE2CF9EA74FCA8F2AF5957EFEEA562"

// elGamalKeyGeneration generates an ECDSA public key from the predefined WMRM public key.
func elGamalKeyGeneration() *ecdsa.PublicKey {
   data, _ := hex.DecodeString(WMRM_PUBLIC_KEY)
   var key ecdsa.PublicKey
   key.X = new(big.Int).SetBytes(data[:32])
   key.Y = new(big.Int).SetBytes(data[32:])
   return &key
}

// elGamalEncrypt encrypts a message m using ElGamal encryption with public key h.
func elGamalEncrypt(m, h *ecdsa.PublicKey) []byte {
   // generator
   g := elliptic.P256()
   // choose an integer y randomly
   y := big.NewInt(1) // In a real scenario, y should be truly random
   // compute c1 := g^y
   c1X, c1Y := g.ScalarBaseMult(y.Bytes())
   // Calculate shared secret s = (h^y)
   sX, sY := g.ScalarMult(h.X, h.Y, y.Bytes())
   // Second component C2 = M + s (point addition for elliptic curves)
   c2X, c2Y := g.Add(m.X, m.Y, sX, sY)
   return slices.Concat(c1X.Bytes(), c1Y.Bytes(), c2X.Bytes(), c2Y.Bytes())
}

// elGamalDecrypt decrypts a ciphertext using ElGamal decryption with private key x.
func elGamalDecrypt(ciphertext []byte, x *ecdsa.PrivateKey) []byte {
   // generator
   g := elliptic.P256()
   // Unmarshal C1 component
   c1X := new(big.Int).SetBytes(ciphertext[:32])
   c1Y := new(big.Int).SetBytes(ciphertext[32:64])
   // Unmarshal C2 component
   c2X := new(big.Int).SetBytes(ciphertext[64:96])
   c2Y := new(big.Int).SetBytes(ciphertext[96:])
   // Calculate shared secret s = C1^x
   sX, sY := g.ScalarMult(c1X, c1Y, x.D.Bytes())
   // Invert the point for subtraction
   sY.Neg(sY)
   sY.Mod(sY, g.Params().P)
   // Recover message point: M = C2 - s
   mX, mY := g.Add(c2X, c2Y, sX, sY)
   return append(mX.Bytes(), mY.Bytes()...)
}

// newLa creates a new XML License Acquisition structure.
func newLa(m *ecdsa.PublicKey, cipherData []byte, kid string) xml.La {
   return xml.La{
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
                  CipherValue: base64.StdEncoding.EncodeToString(
                     elGamalEncrypt(m, elGamalKeyGeneration()),
                  ),
               },
            },
         },
         CipherData: xml.CipherData{
            CipherValue: base64.StdEncoding.EncodeToString(cipherData),
         },
      },
   }
}

// NewEnvelope creates a new SOAP envelope for a license acquisition challenge.
func NewEnvelope(device *LocalDevice, kid string) (*xml.Envelope, error) {
   var key XMLKey
   key.New()
   cipherData, err := getCipherData(&device.CertificateChain, &key)
   if err != nil {
      return nil, err
   }
   la := newLa(&key.PublicKey, cipherData, kid)
   laData, err := la.Marshal()
   if err != nil {
      return nil, err
   }
   laDigest := sha256.Sum256(laData)
   signedInfo := xml.SignedInfo{
      XmlNs: "http://www.w3.org/2000/09/xmldsig#",
      Reference: xml.Reference{
         Uri:         "#SignedData",
         DigestValue: base64.StdEncoding.EncodeToString(laDigest[:]),
      },
   }
   signedData, err := signedInfo.Marshal()
   if err != nil {
      return nil, err
   }
   signedDigest := sha256.Sum256(signedData)
   r, s, err := ecdsa.Sign(Fill('C'), device.SigningKey[0], signedDigest[:])
   if err != nil {
      return nil, err
   }
   sign := append(r.Bytes(), s.Bytes()...)
   return &xml.Envelope{
      Soap: "http://schemas.xmlsoap.org/soap/envelope/",
      Body: xml.Body{
         AcquireLicense: &xml.AcquireLicense{
            XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols",
            Challenge: xml.Challenge{
               Challenge: xml.InnerChallenge{
                  XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols/messages",
                  La:    la,
                  Signature: xml.Signature{
                     SignedInfo:     signedInfo,
                     SignatureValue: base64.StdEncoding.EncodeToString(sign),
                  },
               },
            },
         },
      },
   }, nil
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
   var license LicenseResponse
   err = license.Decode(decoded)
   if err != nil {
      return nil, err
   }
   if !bytes.Equal(license.ECCKeyObject.Value, device.EncryptKey.PublicBytes()) {
      return nil, errors.New("license response is not for this device")
   }
   err = license.ContentKeyObject.Decrypt(
      device.EncryptKey[0], license.AuxKeyObject,
   )
   if err != nil {
      return nil, err
   }
   err = license.Verify(license.ContentKeyObject.Integrity.GUID())
   if err != nil {
      return nil, err
   }
   return license.ContentKeyObject, nil
}

// getCipherData prepares cipher data for the license acquisition challenge.
func getCipherData(chain *Chain, key *XMLKey) ([]byte, error) {
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
   data1, err = aesCBCHandler(data1, key.AesKey(), key.AesIv(), true)
   if err != nil {
      return nil, err
   }
   return append(key.AesIv(), data1...), nil
}

func (c *ContentKey) Decrypt(key *ecdsa.PrivateKey, auxKeys *AuxKeys) error {
   switch c.CipherType {
   case 3:
      decrypted := elGamalDecrypt(c.Value, key)
      c.Integrity.Decode(decrypted)
      decrypted = decrypted[16:]
      copy(c.Key[:], decrypted)
      return nil
   case 6:
      return c.scalable(key, auxKeys)
   }
   return errors.New("cannot decrypt key")
}

func (c *ContentKey) scalable(key *ecdsa.PrivateKey, auxKeys *AuxKeys) error {
   rootKeyInfo := c.Value[:144]
   rootKey := rootKeyInfo[128:]
   leafKeys := c.Value[144:]
   decrypted := elGamalDecrypt(rootKeyInfo[:128], key)
   var (
      ci [16]byte
      ck [16]byte
   )
   for i := range 16 {
      ci[i] = decrypted[i*2]
      ck[i] = decrypted[i*2+1]
   }
   magicConstantZero, err := c.magicConstantZero()
   if err != nil {
      return err
   }
   rgbUplinkXkey := xorKey(ck[:], magicConstantZero)
   contentKeyPrime, err := aesECBHandler(rgbUplinkXkey, ck[:], true)
   if err != nil {
      return err
   }
   auxKeyCalc, err := aesECBHandler(auxKeys.Keys[0].Key[:], contentKeyPrime, true)
   if err != nil {
      return err
   }
   var zero [16]byte
   upLinkXkey := xorKey(auxKeyCalc, zero[:])
   oSecondaryKey, err := aesECBHandler(rootKey, ck[:], true)
   if err != nil {
      return err
   }
   rgbKey, err := aesECBHandler(leafKeys, upLinkXkey, true)
   if err != nil {
      return err
   }
   rgbKey, err = aesECBHandler(rgbKey, oSecondaryKey, true)
   if err != nil {
      return err
   }
   c.Integrity.Decode(rgbKey[:])
   rgbKey = rgbKey[16:]
   copy(c.Key[:], rgbKey)
   return nil
}

// LoadBytes loads an ECDSA private key from bytes.
func (e *EcKey) LoadBytes(data []byte) {
   var public ecdsa.PublicKey
   public.Curve = elliptic.P256()
   public.X, public.Y = public.Curve.ScalarBaseMult(data)
   var private ecdsa.PrivateKey
   private.D = new(big.Int).SetBytes(data)
   private.PublicKey = public
   e[0] = &private
}

// PublicBytes returns the public key bytes.
func (e *EcKey) PublicBytes() []byte {
   return append(e[0].PublicKey.X.Bytes(), e[0].PublicKey.Y.Bytes()...)
}

// New generates a new ECDSA private key.
func (e *EcKey) New() error {
   var err error
   e[0], err = ecdsa.GenerateKey(elliptic.P256(), Fill('A'))
   if err != nil {
      return err
   }
   return nil
}

// Private returns the private key bytes.
func (e EcKey) Private() []byte {
   return e[0].D.Bytes()
}

// Read implements the io.Reader interface for Fill.
func (f Fill) Read(data []byte) (int, error) {
   for index := range data {
      data[index] = byte(f)
   }
   return len(data), nil
}

// UUID returns the GUID as a big-endian UUID byte slice.
func (g *GUID) UUID() []byte {
   data := binary.BigEndian.AppendUint32(nil, g.Data1)
   data = binary.BigEndian.AppendUint16(data, g.Data2)
   data = binary.BigEndian.AppendUint16(data, g.Data3)
   return binary.BigEndian.AppendUint64(data, g.Data4)
}

// GUID returns the GUID as a mixed-endian GUID byte slice (standard PlayReady format).
func (g *GUID) GUID() []byte {
   data := binary.LittleEndian.AppendUint32(nil, g.Data1)
   data = binary.LittleEndian.AppendUint16(data, g.Data2)
   data = binary.LittleEndian.AppendUint16(data, g.Data3)
   return binary.BigEndian.AppendUint64(data, g.Data4)
}

// Decode decodes a byte slice into a GUID structure.
func (g *GUID) Decode(data []byte) {
   g.Data1 = binary.LittleEndian.Uint32(data)
   data = data[4:]
   g.Data2 = binary.LittleEndian.Uint16(data)
   data = data[2:]
   g.Data3 = binary.LittleEndian.Uint16(data)
   data = data[2:]
   g.Data4 = binary.BigEndian.Uint64(data)
}

// Encode encodes a LicenseResponse into a byte slice.
func (l *LicenseResponse) Encode() []byte {
   data := l.Magic[:]
   data = binary.BigEndian.AppendUint16(data, l.Offset)
   data = binary.BigEndian.AppendUint16(data, l.Version)
   data = append(data, l.RightsID[:]...)
   return append(data, l.OuterContainer.Encode()...)
}

// Decode decodes a byte slice into a LicenseResponse structure.
func (l *LicenseResponse) Decode(data []byte) error {
   l.RawData = data
   n := copy(l.Magic[:], data)
   l.Offset = binary.BigEndian.Uint16(data[n:])
   n += 2
   l.Version = binary.BigEndian.Uint16(data[n:])
   n += 2
   n += copy(l.RightsID[:], data[n:])
   n += l.OuterContainer.Decode(data[n:])

   var size int

   for size < int(l.OuterContainer.Length)-16 {
      var value FTLV
      i := value.Decode(l.OuterContainer.Value[size:])
      switch XMRType(value.Type) {
      case GlobalPolicyContainerEntryType: // 2
         // Rakuten
      case PlaybackPolicyContainerEntryType: // 4
         // Rakuten
      case KeyMaterialContainerEntryType: // 9
         var j int
         for j < int(value.Length)-16 {
            var value1 FTLV
            k := value1.Decode(value.Value[j:])

            switch XMRType(value1.Type) {
            case ContentKeyEntryType: // 10
               l.ContentKeyObject = &ContentKey{}
               l.ContentKeyObject.decode(value1.Value)

            case DeviceKeyEntryType: // 42
               l.ECCKeyObject = &ECCKey{}
               l.ECCKeyObject.Decode(value1.Value)

            case AuxKeyEntryType: // 81
               l.AuxKeyObject = &AuxKeys{}
               l.AuxKeyObject.Decode(value1.Value)

            default:
               return errors.New("FTLV.type")
            }
            j += k
         }
      case SignatureEntryType: // 11
         l.SignatureObject = &Signature{}
         l.SignatureObject.decode(value.Value)
         l.SignatureObject.Length = uint16(value.Length)

      default:
         return errors.New("FTLV.type")
      }
      size += i
   }

   return nil
}

// Decode decodes a byte slice into an AuxKeys structure.
func (a *AuxKeys) Decode(data []byte) {
   a.Count = binary.BigEndian.Uint16(data)
   data = data[2:]
   for range a.Count {
      var key AuxKey
      n := key.decode(data)
      a.Keys = append(a.Keys, key)
      data = data[n:]
   }
}

// Decode decodes a byte slice into an AuxKey structure.
func (a *AuxKey) decode(data []byte) int {
   a.Location = binary.BigEndian.Uint32(data)
   n := 4
   n += copy(a.Key[:], data[n:])
   return n
}

// Decode decodes a byte slice into an ECCKey structure.
func (e *ECCKey) Decode(data []byte) {
   e.Curve = binary.BigEndian.Uint16(data)
   data = data[2:]
   e.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   e.Value = data[:e.Length]
}

// Encode encodes an FTLV structure into a byte slice.
func (f *FTLV) Encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, f.Flags)
   data = binary.BigEndian.AppendUint16(data, f.Type)
   data = binary.BigEndian.AppendUint32(data, f.Length)
   return append(data, f.Value...)
}

// Decode decodes a byte slice into an FTLV structure.
func (f *FTLV) Decode(data []byte) int {
   f.Flags = binary.BigEndian.Uint16(data)
   n := 2
   f.Type = binary.BigEndian.Uint16(data[n:])
   n += 2
   f.Length = binary.BigEndian.Uint32(data[n:])
   n += 4
   f.Value = data[n:][:f.Length-8]
   n += int(f.Length) - 8
   return n
}

// New initializes an FTLV structure.
func (f *FTLV) New(flags, Type int, value []byte) {
   f.Flags = uint16(flags)
   f.Type = uint16(Type)
   f.Length = uint32(len(value) + 8)
   f.Value = value
}

// magicConstantZero returns a specific hex-decoded byte slice.
func (*ContentKey) magicConstantZero() ([]byte, error) {
   return hex.DecodeString("7ee9ed4af773224f00b8ea7efb027cbb")
}

// decode decodes a byte slice into a ContentKey structure.
func (c *ContentKey) decode(data []byte) {
   c.KeyID.Decode(data[:])
   data = data[16:]
   c.KeyType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.CipherType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.Value = data[:c.Length]
}

// decode decodes a byte slice into a Signature structure.
func (s *Signature) decode(data []byte) {
   s.Type = binary.BigEndian.Uint16(data)
   data = data[2:]
   s.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   s.Data = data
}

// Verify verifies the license response signature.
func (l *LicenseResponse) Verify(contentIntegrity []byte) error {
   data := l.Encode()
   data = data[:len(l.RawData)-int(l.SignatureObject.Length)]
   block, err := aes.NewCipher(contentIntegrity)
   if err != nil {
      return err
   }
   data = mac.NewCMAC(block, aes.BlockSize).MAC(data)
   if !bytes.Equal(data, l.SignatureObject.Data) {
      return errors.New("failed to decrypt the keys")
   }
   return nil
}

// aesECBHandler performs AES ECB encryption/decryption.
// Encrypts if encrypt is true, decrypts otherwise.
func aesECBHandler(data, key []byte, encrypt bool) ([]byte, error) {
   if encrypt {
      bin := crypto.FromBytes(data).WithKey(key).
         Aes().ECB().NoPadding().Encrypt()
      return bin.ToBytes(), bin.Error()
   } else {
      bin := crypto.FromBytes(data).WithKey(key).
         Aes().ECB().NoPadding().Decrypt()
      return bin.ToBytes(), bin.Error()
   }
}

// aesCBCHandler performs AES CBC encryption/decryption with PKCS7 padding.
// Encrypts if encrypt is true, decrypts otherwise.
func aesCBCHandler(data, key, iv []byte, encrypt bool) ([]byte, error) {
   if encrypt {
      bin := crypto.FromBytes(data).WithKey(key).WithIv(iv).
         Aes().CBC().PKCS7Padding().Encrypt()
      return bin.ToBytes(), bin.Error()
   } else {
      bin := crypto.FromBytes(data).WithKey(key).WithIv(iv).
         Aes().CBC().PKCS7Padding().Decrypt()
      return bin.ToBytes(), bin.Error()
   }
}

// New initializes a new XMLKey.
func (x *XMLKey) New() {
   x.PublicKey.X, x.PublicKey.Y = elliptic.P256().ScalarBaseMult([]byte{1})
   x.PublicKey.X.FillBytes(x.X[:])
}

// AesIv returns the AES IV from the XMLKey's internal data.
func (x *XMLKey) AesIv() []byte {
   return x.X[:16]
}

// AesKey returns the AES Key from the XMLKey's internal data.
func (x *XMLKey) AesKey() []byte {
   return x.X[16:]
}

// xorKey performs XOR operation on two byte slices.
func xorKey(a, b []byte) []byte {
   if len(a) != len(b) {
      panic("slices have different lengths")
   }
   c := make([]byte, len(a))
   for i := 0; i < len(a); i++ {
      c[i] = a[i] ^ b[i]
   }
   return c
}

// ecdsaSignature represents an ECDSA signature structure within a certificate.
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

// LocalDevice represents a device with its certificate chain and keys.
type LocalDevice struct {
   CertificateChain Chain
   EncryptKey       EcKey
   SigningKey       EcKey
}

// Chain represents a chain of certificates.
type Chain struct {
   magic     [4]byte
   version   uint32
   length    uint32
   flags     uint32
   certCount uint32
   certs     []Cert
}

// Cert represents a single certificate within a chain. Renamed to Cert to avoid conflict with package name convention.
type Cert struct {
   magic             [4]byte
   version           uint32
   length            uint32
   lengthToSignature uint32
   rawData           []byte
   certificateInfo   *CertInfo
   features          *Feature
   keyData           *KeyInfo
   manufacturerInfo  *Manufacturer
   signatureData     *ecdsaSignature
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
      builtKeyInfo     KeyInfo
      certificateInfo  CertInfo
      signatureData    ecdsaSignature
      signatureFtlv    FTLV
      deviceFtlv       FTLV
      featureFtlv      FTLV
      keyInfoFtlv      FTLV
      manufacturerFtlv FTLV
      certificateFtlv  FTLV
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
   var newDevice Device
   newDevice.New()
   deviceFtlv.New(1, 4, newDevice.Encode())

   // Create FTLV for key information.
   keyInfoFtlv.New(1, 6, builtKeyInfo.encode())

   // Create FTLV for manufacturer information, copying from the existing chain's first cert.
   manufacturerFtlv.New(0, 7, c.certs[0].manufacturerInfo.encode())

   // Define feature for the new certificate.
   feature := Feature{
      entries:  1,
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
   var unsignedCert Cert
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
      var cert1 Cert
      i, err := cert1.decode(data)
      if err != nil {
         return err
      }
      data = data[i:]
      c.certs = append(c.certs, cert1)
   }
   return nil
}

// decode decodes a byte slice into the Cert structure.
func (c *Cert) decode(data []byte) (int, error) {
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
      var ftlv FTLV
      j := ftlv.Decode(c.rawData[sum:])

      switch ftlv.Type {
      case objTypeBasic:
         c.certificateInfo = &CertInfo{}
         c.certificateInfo.decode(ftlv.Value)

      case objTypeFeature:
         c.features = &Feature{}
         c.features.decode(ftlv.Value)

      case objTypeKey:
         c.keyData = &KeyInfo{}
         c.keyData.decode(ftlv.Value)

      case objTypeManufacturer:
         c.manufacturerInfo = &Manufacturer{}
         err := c.manufacturerInfo.decode(ftlv.Value)
         if err != nil {
            return 0, err
         }

      case objTypeSignature:
         c.signatureData = &ecdsaSignature{}
         c.signatureData.Decode(ftlv.Value)

      }

      sum += j
   }

   return n, nil
}

// newNoSig initializes a new Cert without signature data.
func (c *Cert) newNoSig(data []byte) {
   copy(c.magic[:], "CERT")
   c.version = 1
   // length = length of raw data + header size (16) + signature size (144)
   c.length = uint32(len(data)) + 16 + 144
   // lengthToSignature = length of raw data + header size (16)
   c.lengthToSignature = uint32(len(data)) + 16
   c.rawData = data
}

// verify verifies the signature of the certificate using the provided public key.
func (c *Cert) verify(pubKey []byte) bool {
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
func (c *Cert) encode() []byte {
   data := c.magic[:]
   data = binary.BigEndian.AppendUint32(data, c.version)
   data = binary.BigEndian.AppendUint32(data, c.length)
   data = binary.BigEndian.AppendUint32(data, c.lengthToSignature)
   return append(data, c.rawData[:]...)
}

// Feature represents a feature set within a certificate. Renamed to avoid conflict.
type Feature struct {
   entries  uint32
   features []uint32
}

// decode decodes a byte slice into the Feature structure.
func (f *Feature) decode(data []byte) int {
   f.entries = binary.BigEndian.Uint32(data)
   n := 4
   for range f.entries {
      f.features = append(f.features, binary.BigEndian.Uint32(data[n:]))
      n += 4
   }
   return n
}

// New initializes a new Feature with a given type.
func (f *Feature) New(Type int) {
   f.entries = 1
   f.features = []uint32{uint32(Type)}
}

// encode encodes the Feature structure into a byte slice.
func (f *Feature) encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, f.entries)

   for i := range f.entries {
      data = binary.BigEndian.AppendUint32(data, f.features[i])
   }

   return data
}

// Device represents device capabilities. Renamed to avoid conflict.
type Device struct {
   maxLicenseSize       uint32
   maxHeaderSize        uint32
   maxLicenseChainDepth uint32
}

// New initializes default device capabilities.
func (d *Device) New() {
   d.maxLicenseSize = 10240
   d.maxHeaderSize = 15360
   d.maxLicenseChainDepth = 2
}

// Encode encodes device capabilities into a byte slice.
func (d *Device) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, d.maxLicenseSize)
   data = binary.BigEndian.AppendUint32(data, d.maxHeaderSize)
   return binary.BigEndian.AppendUint32(data, d.maxLicenseChainDepth)
}

// Key represents a cryptographic key within KeyInfo. Renamed to avoid conflict.
type Key struct {
   keyType   uint16
   length    uint16
   flags     uint32
   publicKey [64]byte // ECDSA P256 public key is 64 bytes (X and Y coordinates, 32 bytes each)
   usage     Feature  // Features indicating key usage
}

// New initializes a new Key with provided data and type.
func (k *Key) New(keyData []byte, Type int) {
   k.keyType = 1  // Assuming type 1 is for ECDSA keys
   k.length = 512 // Assuming key length in bits
   copy(k.publicKey[:], keyData)
   k.usage.New(Type)
}

// encode encodes the Key structure into a byte slice.
func (k *Key) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, k.keyType)
   data = binary.BigEndian.AppendUint16(data, k.length)
   data = binary.BigEndian.AppendUint32(data, k.flags)
   data = append(data, k.publicKey[:]...)
   return append(data, k.usage.encode()...)
}

// decode decodes a byte slice into the Key structure.
func (k *Key) decode(data []byte) int {
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

// KeyInfo represents information about multiple keys. Renamed to avoid conflict.
type KeyInfo struct {
   entries uint32
   keys    []Key
}

// New initializes a new KeyInfo with signing and encryption keys.
func (k *KeyInfo) New(signingKey, encryptKey []byte) {
   k.entries = 2
   k.keys = make([]Key, 2)
   k.keys[0].New(signingKey, 1) // Type 1 for signing key
   k.keys[1].New(encryptKey, 2) // Type 2 for encryption key
}

// encode encodes the KeyInfo structure into a byte slice.
func (k *KeyInfo) encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, k.entries)

   for i := range k.entries {
      data = append(data, k.keys[i].encode()...)
   }

   return data
}

// decode decodes a byte slice into the KeyInfo structure.
func (k *KeyInfo) decode(data []byte) {
   k.entries = binary.BigEndian.Uint32(data)
   data = data[4:]
   for range k.entries {
      var key_data Key
      n := key_data.decode(data)
      k.keys = append(k.keys, key_data)
      data = data[n:]
   }
}

// ManufacturerInfo contains a length-prefixed string. Renamed to avoid conflict.
type ManufacturerInfo struct {
   length uint32
   value  string
}

// encode encodes the ManufacturerInfo structure into a byte slice.
func (m *ManufacturerInfo) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, m.length)
   return append(data, []byte(m.value)...)
}

// decode decodes a byte slice into the ManufacturerInfo structure.
func (m *ManufacturerInfo) decode(data []byte) int {
   m.length = binary.BigEndian.Uint32(data)
   n := 4
   // Data is padded to a multiple of 4 bytes.
   padded_length := (m.length + 3) &^ 3
   m.value = string(data[n:][:padded_length])
   n += int(padded_length)
   return n
}

// Manufacturer represents manufacturer details. Renamed to avoid conflict.
type Manufacturer struct {
   flags            uint32
   manufacturerName ManufacturerInfo
   modelName        ManufacturerInfo
   modelNumber      ManufacturerInfo
}

// encode encodes the Manufacturer structure into a byte slice.
func (m *Manufacturer) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, m.flags)
   data = append(data, m.manufacturerName.encode()...)
   data = append(data, m.modelName.encode()...)
   return append(data, m.modelNumber.encode()...)
}

// decode decodes a byte slice into the Manufacturer structure.
func (m *Manufacturer) decode(data []byte) error {
   m.flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   n := m.manufacturerName.decode(data)
   data = data[n:]
   n = m.modelName.decode(data)
   data = data[n:]
   m.modelNumber.decode(data)
   return nil
}

// CertInfo contains basic certificate information. Renamed to avoid conflict.
type CertInfo struct {
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

// encode encodes the CertInfo structure into a byte slice.
func (c *CertInfo) encode() []byte {
   data := c.certificateId[:]
   data = binary.BigEndian.AppendUint32(data, c.securityLevel)
   data = binary.BigEndian.AppendUint32(data, c.flags)
   data = binary.BigEndian.AppendUint32(data, c.infoType)
   data = append(data, c.digest[:]...)
   data = binary.BigEndian.AppendUint32(data, c.expiry)
   return append(data, c.clientId[:]...)
}

// New initializes a new CertInfo with security level and digest.
func (c *CertInfo) New(securityLevel uint32, digest []byte) {
   c.securityLevel = securityLevel
   c.infoType = 2 // Assuming infoType 2 is a standard type
   copy(c.digest[:], digest)
   c.expiry = 4294967295 // Max uint32, effectively never expires
}

// decode decodes a byte slice into the CertInfo structure.
func (c *CertInfo) decode(data []byte) {
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

type Fill byte

type GUID struct {
   Data1 uint32 // little endian
   Data2 uint16 // little endian
   Data3 uint16 // little endian
   Data4 uint64 // big endian
}

type LicenseResponse struct {
   RawData          []byte
   Magic            [4]byte
   Offset           uint16
   Version          uint16
   RightsID         [16]byte
   OuterContainer   FTLV
   ContentKeyObject *ContentKey
   ECCKeyObject     *ECCKey
   SignatureObject  *Signature
   AuxKeyObject     *AuxKeys
}

type AuxKeys struct {
   Count uint16
   Keys  []AuxKey
}

type AuxKey struct {
   Location uint32
   Key      [16]byte
}

type ECCKey struct {
   Curve  uint16
   Length uint16
   Value  []byte
}

// FTLV is renamed from the original `FTLV` in `zero` to avoid conflict if `cert` also had an FTLV.
// Since `cert` already referenced `zero.FTLV`, the type definition from `zero` is used.
type FTLV struct {
   Flags  uint16
   Type   uint16
   Length uint32
   Value  []byte
}

type ContentKey struct {
   KeyID      GUID
   KeyType    uint16
   CipherType uint16
   Length     uint16
   Value      []byte
   Integrity  GUID
   Key        [16]byte
}

type XMRType uint16

const (
   OuterContainerEntryType                 XMRType = 1
   GlobalPolicyContainerEntryType          XMRType = 2
   PlaybackPolicyContainerEntryType        XMRType = 4
   MinimumOutputProtectionLevelsEntryType  XMRType = 5
   ExplicitAnalogVideoProtectionEntryType  XMRType = 7
   AnalogVideoOPLEntryType                 XMRType = 8
   KeyMaterialContainerEntryType           XMRType = 9
   ContentKeyEntryType                     XMRType = 10
   SignatureEntryType                      XMRType = 11
   SerialNumberEntryType                   XMRType = 12
   RightsEntryType                         XMRType = 13
   ExpirationEntryType                     XMRType = 18
   IssueDateEntryType                      XMRType = 19
   MeteringEntryType                       XMRType = 22
   GracePeriodEntryType                    XMRType = 26
   SourceIDEntryType                       XMRType = 34
   RestrictedSourceIDEntryType             XMRType = 40
   DomainIDEntryType                       XMRType = 41
   DeviceKeyEntryType                      XMRType = 42
   PolicyMetadataEntryType                 XMRType = 44
   OptimizedContentKeyEntryType            XMRType = 45
   ExplicitDigitalAudioProtectionEntryType XMRType = 46
   ExpireAfterFirstUseEntryType            XMRType = 48
   DigitalAudioOPLEntryType                XMRType = 49
   RevocationInfoVersionEntryType          XMRType = 50
   EmbeddingBehaviorEntryType              XMRType = 51
   SecurityLevelEntryType                  XMRType = 52
   MoveEnablerEntryType                    XMRType = 55
   UplinkKIDEntryType                      XMRType = 59
   CopyPoliciesContainerEntryType          XMRType = 60
   CopyCountEntryType                      XMRType = 61
   RemovalDateEntryType                    XMRType = 80
   AuxKeyEntryType                         XMRType = 81
   UplinkXEntryType                        XMRType = 82
   RealTimeExpirationEntryType             XMRType = 85
   ExplicitDigitalVideoProtectionEntryType XMRType = 88
   DigitalVideoOPLEntryType                XMRType = 89
   SecureStopEntryType                     XMRType = 90
   CopyUnknownObjectEntryType              XMRType = 65533
   GlobalPolicyUnknownObjectEntryType      XMRType = 65533
   PlaybackUnknownObjectEntryType          XMRType = 65533
   CopyUnknownContainerEntryType           XMRType = 65534
   UnknownContainersEntryType              XMRType = 65534
   PlaybackUnknownContainerEntryType       XMRType = 65534
)

type Signature struct {
   Type   uint16
   Length uint16
   Data   []byte
}

type EcKey [1]*ecdsa.PrivateKey

type XMLKey struct {
   PublicKey ecdsa.PublicKey
   X         [32]byte
}
