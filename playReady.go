package playReady

import (
   "41.neocities.org/playReady/certificate"
   "bytes"
   "crypto/aes"
   "crypto/cipher"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/sha256"
   "crypto/x509"
   "encoding/base64"
   "encoding/binary"
   "encoding/hex"
   "encoding/pem"
   "encoding/xml"
   "errors"
   "fmt"
   "github.com/deatil/go-cryptobin/mode"
   "math/big"
   "os"
)

var Fill Filler = '!'

func (a Aes) EncryptECB(key []byte, data []byte) []byte {
   block, _ := aes.NewCipher(key)
   ciphertext := make([]byte, len(data))
   ecbMode := mode.NewECBEncrypter(block)
   ecbMode.CryptBlocks(ciphertext, data)
   return ciphertext
}

func (a Aes) EncryptCbc(key *XmlKey, data []byte) ([]byte, error) {
   block, err := aes.NewCipher(key.AesKey[:])
   if err != nil {
      return nil, err
   }
   data = a.Pad(data)
   ciphertext := make([]byte, len(data))
   cipher.NewCBCEncrypter(block, key.AesIv[:]).CryptBlocks(ciphertext, data)
   return ciphertext, nil
}

type XmlKey struct {
   AesIv     [16]byte
   AesKey    [16]byte
   PublicKey ecdsa.PublicKey
}

func (WMRM) Points() (*big.Int, *big.Int, error) {
   bytes, err := hex.DecodeString(WMRMPublicKey)
   if err != nil {
      return nil, nil, fmt.Errorf("decoding hex string: %v", err)
   }
   x := new(big.Int).SetBytes(bytes[:32])
   y := new(big.Int).SetBytes(bytes[32:])
   return x, y, nil
}

func (e *EcKey) LoadBytes(data []byte) {
   var public ecdsa.PublicKey
   public.Curve = elliptic.P256()
   public.X, public.Y = public.Curve.ScalarBaseMult(data)
   var private ecdsa.PrivateKey
   private.D = new(big.Int).SetBytes(data)
   private.PublicKey = public
   e.Key = &private
}

func (e *EcKey) LoadFile(path string) error {
   keyFile, err := os.ReadFile(path)
   if err != nil {
      return err
   }
   block, _ := pem.Decode(keyFile)
   if block == nil {
      e.LoadBytes(keyFile)
      return nil
   }
   key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
   if err != nil {
      return err
   }
   e.Key = key.(*ecdsa.PrivateKey)
   return nil
}

func (e *EcKey) PublicBytes() []byte {
   SigningX, SigningY := e.Key.PublicKey.X.Bytes(), e.Key.PublicKey.Y.Bytes()
   SigningPublicKey := SigningX
   SigningPublicKey = append(SigningPublicKey, SigningY...)
   return SigningPublicKey
}

type ElGamal struct{}

func (ElGamal) Decrypt(ciphertext []byte, PrivateKey *big.Int) []byte {
   curveData := elliptic.P256()

   x1, y1 := new(big.Int).SetBytes(ciphertext[:32]), new(big.Int).SetBytes(ciphertext[32:64])
   x2, y2 := new(big.Int).SetBytes(ciphertext[64:96]), new(big.Int).SetBytes(ciphertext[96:128])

   SX, SY := curveData.ScalarMult(x1, y1, PrivateKey.Bytes())

   NegSY := new(big.Int).Sub(curveData.Params().P, SY)

   NegSY.Mod(NegSY, curveData.Params().P)

   PX, PY := curveData.Add(x2, y2, SX, NegSY)

   Decrypted := PX.Bytes()

   return append(Decrypted, PY.Bytes()...)
}

type Aes struct{}

func (Aes) Pad(data []byte) []byte {
   length := aes.BlockSize - len(data)%aes.BlockSize
   for high := byte(length); length >= 1; length-- {
      data = append(data, high)
   }
   return data
}

type WMRM struct{}

var WMRMPublicKey = "C8B6AF16EE941AADAA5389B4AF2C10E356BE42AF175EF3FACE93254E7B0B3D9B982B27B5CB2341326E56AA857DBFD5C634CE2CF9EA74FCA8F2AF5957EFEEA562"

func (e EcKey) Private() []byte {
   var data [32]byte
   e.Key.D.FillBytes(data[:])
   return data[:]
}

type EcKey struct {
   Key *ecdsa.PrivateKey
}

type Filler byte

// github.com/golang/go/issues/58454
func (f Filler) Read(data []byte) (int, error) {
   for index := range data {
      data[index] = byte(f)
   }
   return len(data), nil
}

func (e *EcKey) New() error {
   var err error
   e.Key, err = ecdsa.GenerateKey(elliptic.P256(), Fill)
   if err != nil {
      return err
   }
   return nil
}

func (x *XmlKey) New() error {
   key, err := ecdsa.GenerateKey(elliptic.P256(), Fill)
   if err != nil {
      return err
   }
   x.PublicKey = key.PublicKey
   Aes := x.PublicKey.X.Bytes()
   n := copy(x.AesIv[:], Aes)
   Aes = Aes[n:]
   copy(x.AesKey[:], Aes)
   return nil
}

func (ElGamal) Encrypt(
   PubX *big.Int, PubY *big.Int, plaintext *XmlKey,
) ([]byte, error) {
   curveData := elliptic.P256()
   curve_int := big.NewInt(1)
   C1X, C1Y := curveData.ScalarMult(
      curveData.Params().Gx, curveData.Params().Gy, curve_int.Bytes(),
   )
   C2XMulti, C2YMulti := curveData.ScalarMult(PubX, PubY, curve_int.Bytes())
   C2X, C2Y := curveData.Add(
      plaintext.PublicKey.X, plaintext.PublicKey.Y, C2XMulti, C2YMulti,
   )
   Encrypted := C1X.Bytes()
   Encrypted = append(Encrypted, C1Y.Bytes()...)
   Encrypted = append(Encrypted, C2X.Bytes()...)
   return append(Encrypted, C2Y.Bytes()...), nil
}
func get_cipher_data(
   cert_chain *Chain, key *XmlKey,
) ([]byte, error) {
   data1, err := xml.Marshal(Data{
      CertificateChains: CertificateChains{
         CertificateChain: base64.StdEncoding.EncodeToString(cert_chain.Encode()),
      },
   })
   if err != nil {
      return nil, err
   }
   var aes Aes
   ciphertext, err := aes.EncryptCbc(key, data1)
   if err != nil {
      return nil, err
   }
   return append(key.AesIv[:], ciphertext...), nil
}

func (e *Envelope) New(
   cert_chain *Chain, signing_key EcKey, kid string,
) error {
   var key XmlKey
   err := key.New()
   if err != nil {
      return err
   }
   cipher_data, err := get_cipher_data(cert_chain, &key)
   if err != nil {
      return err
   }
   var la_value La
   err = la_value.New(&key, cipher_data, kid)
   if err != nil {
      return err
   }
   la_data, err := xml.Marshal(la_value)
   if err != nil {
      return err
   }
   la_digest := sha256.Sum256(la_data)
   var signed_info SignedInfo
   signed_info.New(la_digest[:])
   signed_data, err := xml.Marshal(signed_info)
   if err != nil {
      return err
   }
   signed_digest := sha256.Sum256(signed_data)
   r, s, err := ecdsa.Sign(Fill, signing_key.Key, signed_digest[:])
   if err != nil {
      return err
   }
   sig := append(r.Bytes(), s.Bytes()...)
   *e = Envelope{
      Soap: "http://schemas.xmlsoap.org/soap/envelope/",
      Body: Body{
         AcquireLicense: AcquireLicense{
            XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols",
            Challenge: Challenge{
               Challenge: InnerChallenge{
                  XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols/messages",
                  La: la_value,
                  Signature: Signature{
                     SignedInfo:     signed_info,
                     SignatureValue: base64.StdEncoding.EncodeToString(sig),
                  },
               },
            },
         },
      },
   }
   return nil
}

type Device struct {
   MaxLicenseSize       uint32
   MaxHeaderSize        uint32
   MaxLicenseChainDepth uint32
}

func (d *Device) New() {
   d.MaxLicenseSize = uint32(10240)
   d.MaxHeaderSize = uint32(15360)
   d.MaxLicenseChainDepth = uint32(2)
}

func (d *Device) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, d.MaxLicenseSize)
   data = binary.BigEndian.AppendUint32(data, d.MaxHeaderSize)
   return binary.BigEndian.AppendUint32(data, d.MaxLicenseChainDepth)
}

func (f *FTLV) New(Flags, Type int, Value []byte) {
   f.Flags = uint16(Flags)
   f.Type = uint16(Type)
   f.Length = uint32(len(Value) + 8)
   f.Value = Value
}

type Header struct {
   Record    *PlayReadyRecord
   Object    *PlayReadyObject
}

type ManufacturerInfo struct {
   Length uint32
   Value  string
}

func (m *ManufacturerInfo) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint32(data, m.Length)
   data = append(data, []byte(m.Value)...)

   return data
}

func (m *ManufacturerInfo) Decode(data []byte) (uint32, error) {
   m.Length = binary.BigEndian.Uint32(data)
   var n uint32 = 4

   paddedLength := (m.Length + 3) &^ 3

   m.Value = string(data[n:][:paddedLength])

   n += paddedLength

   return n, nil
}

type ObjType uint16

const (
   BASIC ObjType = iota + 1
   DOMAIN
   PC
   DEVICE
   FEATURE
   KEY
   MANUFACTURER
   SIGNATURE
   SILVERLIGHT
   METERING
   EXTDATASIGNKEY
   EXTDATACONTAINER
   EXTDATASIGNATURE
   EXTDATA_HWIO
   SERVER
   SECURITY_VERSION
   SECURITY_VERSION_2
)

type PlayReadyObject struct {
   Type   uint16
   Length uint16
   Data   string
}

func (p *PlayReadyRecord) Decode(data []byte) bool {
   p.Length = binary.LittleEndian.Uint32(data)
   if int(p.Length) > len(data) {
      return false
   }
   data = data[4:]
   p.Count = binary.LittleEndian.Uint16(data)
   data = data[2:]
   p.Data = data
   return true
}

type PlayReadyRecord struct {
   Length uint32
   Count  uint16
   Data   []byte
}
type Cert struct {
   Magic             [4]byte
   Version           uint32
   Length            uint32
   LengthToSignature uint32
   RawData           []byte
   CertificateInfo   *CertInfo
   Features          *certificate.Feature
   KeyData           *certificate.KeyInfo
   ManufacturerInfo  *Manufacturer
   SignatureData     *certificate.Signature
}

func (c *Cert) Verify(PubKey []byte) bool {
   if !bytes.Equal(c.SignatureData.IssuerKey, PubKey) {
      return false
   }
   data := c.Encode()
   data = data[:c.LengthToSignature]
   x := new(big.Int).SetBytes(PubKey[:32])
   y := new(big.Int).SetBytes(PubKey[32:])
   PublicKey := &ecdsa.PublicKey{
      Curve: elliptic.P256(),
      X:     x,
      Y:     y,
   }
   Sig := c.SignatureData.SignatureData
   SignatureDigest := sha256.Sum256(data)
   r, s := new(big.Int).SetBytes(Sig[:32]), new(big.Int).SetBytes(Sig[32:])
   return ecdsa.Verify(PublicKey, SignatureDigest[:], r, s)
}

func (c *Cert) Decode(data []byte) (int, error) {
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
   c.RawData = data[n:][:c.Length-16]
   n += len(c.RawData)

   var sum uint32
   for sum < c.Length-16 {
      var ftlv FTLV

      j, err := ftlv.Decode(c.RawData[sum:])

      if err != nil {
         return 0, err
      }

      var ObjectType = ObjType(ftlv.Type)

      switch ObjectType {
      case BASIC:
         c.CertificateInfo = new(CertInfo)

         err := c.CertificateInfo.Decode(ftlv.Value)

         if err != nil {
            return 0, err
         }

      case FEATURE:
         c.Features = new(certificate.Feature)

         _, err := c.Features.Decode(ftlv.Value)
         if err != nil {
            return 0, err
         }

      case KEY:
         c.KeyData = new(certificate.KeyInfo)
         err := c.KeyData.Decode(ftlv.Value)
         if err != nil {
            return 0, err
         }

      case MANUFACTURER:
         c.ManufacturerInfo = new(Manufacturer)

         err := c.ManufacturerInfo.Decode(ftlv.Value)

         if err != nil {
            return 0, err
         }

      case SIGNATURE:
         c.SignatureData = new(certificate.Signature)
         err := c.SignatureData.Decode(ftlv.Value)

         if err != nil {
            return 0, err
         }

      }

      sum += j
   }

   return n, nil
}

func (c *Cert) Encode() []byte {
   var data []byte
   data = append(data, c.Magic[:]...)

   data = binary.BigEndian.AppendUint32(data, c.Version)
   data = binary.BigEndian.AppendUint32(data, c.Length)
   data = binary.BigEndian.AppendUint32(data, c.LengthToSignature)

   return append(data, c.RawData[:]...)
}

func (c *Cert) NewNoSig(Value []byte) {
   copy(c.Magic[:], "CERT")
   c.Version = 1
   c.Length = uint32(len(Value)) + 16 + 144
   c.LengthToSignature = uint32(len(Value)) + 16
   c.RawData = make([]byte, len(Value))
   copy(c.RawData, Value)
}

type CertInfo struct {
   CertificateId [16]byte
   SecurityLevel uint32
   Flags         uint32
   Type          uint32
   Digest        [32]byte
   Expiry        uint32
   ClientId      [16]byte
}

func (c *CertInfo) New(SecurityLevel uint32, Digest []byte) {
   c.SecurityLevel = SecurityLevel
   c.Flags = 0
   c.Type = 2
   copy(c.Digest[:], Digest)
   c.Expiry = 4294967295
}

func (c *CertInfo) Decode(data []byte) error {
   n := copy(c.CertificateId[:], data)
   data = data[n:]
   c.SecurityLevel = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.Flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.Type = binary.BigEndian.Uint32(data)
   data = data[4:]
   n = copy(c.Digest[:], data)
   data = data[n:]
   c.Expiry = binary.BigEndian.Uint32(data)
   data = data[4:]
   copy(c.ClientId[:], data)
   return nil
}

func (c *CertInfo) Encode() []byte {
   data := c.CertificateId[:]
   data = binary.BigEndian.AppendUint32(data, c.SecurityLevel)
   data = binary.BigEndian.AppendUint32(data, c.Flags)
   data = binary.BigEndian.AppendUint32(data, c.Type)
   data = append(data, c.Digest[:]...)
   data = binary.BigEndian.AppendUint32(data, c.Expiry)
   return append(data, c.ClientId[:]...)
}

type Manufacturer struct {
   Flags            uint32
   ManufacturerName ManufacturerInfo
   ModelName        ManufacturerInfo
   ModelNumber      ManufacturerInfo
}

func (m *Manufacturer) Encode() []byte {
   var data []byte

   data = binary.BigEndian.AppendUint32(data, m.Flags)
   data = append(data, m.ManufacturerName.Encode()...)
   data = append(data, m.ModelName.Encode()...)
   data = append(data, m.ModelNumber.Encode()...)

   return data
}

func (m *Manufacturer) Decode(data []byte) error {
   m.Flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   n, err := m.ManufacturerName.Decode(data)
   if err != nil {
      return err
   }
   data = data[n:]
   n, err = m.ModelName.Decode(data)
   if err != nil {
      return err
   }
   data = data[n:]
   _, err = m.ModelNumber.Decode(data)
   if err != nil {
      return err
   }
   return nil
}
