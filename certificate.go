package playReady

import (
   "bytes"
   "crypto/sha256"
   "encoding/binary"
   "encoding/hex"
   "errors"
   "github.com/arnaucube/cryptofun/ecc"
   "math/big"
)

func (c *ContentKey) scalable(key *big.Int, aux *AuxKeys) (*xCoord, error) {
   rootKeyInfo, leafKeys := c.Value[:144], c.Value[144:]
   rootKey := rootKeyInfo[128:]
   decrypt, err := elGamalDecrypt(rootKeyInfo[:128], key)
   if err != nil {
      return nil, err
   }
   var coord xCoord
   coord.New(decrypt.X)
   var (
      ci [16]byte
      ck [16]byte
   )
   for i := range 16 {
      ci[i] = coord[i*2]
      ck[i] = coord[i*2+1]
   }
   constantZero, err := hex.DecodeString(magicConstantZero)
   if err != nil {
      return nil, err
   }
   rgbUplinkXkey := xorKey(ck[:], constantZero)
   contentKeyPrime, err := aesEcbEncrypt(rgbUplinkXkey, ck[:])
   if err != nil {
      return nil, err
   }
   auxKeyCalc, err := aesEcbEncrypt(aux.Keys[0].Key[:], contentKeyPrime)
   if err != nil {
      return nil, err
   }
   oSecondaryKey, err := aesEcbEncrypt(rootKey, ck[:])
   if err != nil {
      return nil, err
   }
   rgbKey, err := aesEcbEncrypt(leafKeys, auxKeyCalc)
   if err != nil {
      return nil, err
   }
   rgbKey, err = aesEcbEncrypt(rgbKey, oSecondaryKey)
   if err != nil {
      return nil, err
   }
   return (*xCoord)(rgbKey), nil
}

func (c *Certificate) verify(pubK []byte) (bool, error) {
   if !bytes.Equal(c.Signature.IssuerKey, pubK) {
      return false, nil
   }
   hashVal := func() *big.Int {
      data := c.Append(nil)
      data = data[:c.LengthToSignature]
      sum := sha256.Sum256(data)
      return new(big.Int).SetBytes(sum[:])
   }()
   sign := c.Signature.Signature
   return p256().dsa().Verify(
      hashVal,
      [2]*big.Int{
         new(big.Int).SetBytes(sign[:32]),
         new(big.Int).SetBytes(sign[32:]),
      },
      ecc.Point{
         X: new(big.Int).SetBytes(pubK[:32]),
         Y: new(big.Int).SetBytes(pubK[32:]),
      },
   )
}

func (c *Certificate) decode(data []byte) (int, error) {
   // Copy the magic bytes and check for "CERT" signature.
   n := copy(c.Magic[:], data)
   if string(c.Magic[:]) != "CERT" {
      return 0, errors.New("failed to find cert magic")
   }
   // Decode Version, Length, and LengthToSignature fields.
   c.Version = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.Length = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.LengthToSignature = binary.BigEndian.Uint32(data[n:])
   n += 4
   for n < int(c.Length) {
      var value Ftlv
      bytesReadFromFtlv, err := value.decode(data[n:])
      if err != nil {
         return 0, err
      }
      switch value.Type {
      case objTypeBasic: // 0x0001
         c.Info = &CertificateInfo{}
         c.Info.decode(value.Value)
      case objTypeFeature: // 0x0005
         c.Features = &value
      case objTypeKey: // 0x0006
         c.KeyInfo = &KeyInfo{}
         c.KeyInfo.decode(value.Value)
      case objTypeManufacturer: // 0x0007
         c.Manufacturer = &value
      case objTypeSignature: // 0x0008
         c.Signature = &CertSignature{}
         err := c.Signature.decode(value.Value)
         if err != nil {
            return 0, err
         }
      default:
         return 0, errors.New("Ftlv.Type")
      }
      n += bytesReadFromFtlv
   }
   return n, nil // Return total bytes consumed and nil for no error
}

type Certificate struct {
   Magic             [4]byte          // bytes 0 - 3
   Version           uint32           // bytes 4 - 7
   Length            uint32           // bytes 8 - 11
   LengthToSignature uint32           // bytes 12 - 15
   Info              *CertificateInfo // type 1
   Features          *Ftlv            // type 5
   KeyInfo           *KeyInfo         // type 6
   Manufacturer      *Ftlv            // type 7
   Signature         *CertSignature   // type 8
}

func (c *Certificate) Append(data []byte) []byte {
   data = append(data, c.Magic[:]...)
   data = binary.BigEndian.AppendUint32(data, c.Version)
   data = binary.BigEndian.AppendUint32(data, c.Length)
   data = binary.BigEndian.AppendUint32(data, c.LengthToSignature)
   if c.Info != nil {
      data = c.Info.ftlv(1, 1).Append(data)
   }
   if c.Features != nil {
      data = c.Features.Append(data)
   }
   if c.KeyInfo != nil {
      data = c.KeyInfo.ftlv(1, 6).Append(data)
   }
   if c.Manufacturer != nil {
      data = c.Manufacturer.Append(data)
   }
   if c.Signature != nil {
      data = c.Signature.ftlv(0, 8).Append(data)
   }
   return data
}

func (c *Certificate) size() (uint32, uint32) {
   n := len(c.Magic)
   n += 4 // Version
   n += 4 // Length
   n += 4 // LengthToSignature
   if c.Info != nil {
      n += new(Ftlv).size()
      n += binary.Size(c.Info)
   }
   if c.Features != nil {
      n += c.Features.size()
   }
   if c.KeyInfo != nil {
      n += new(Ftlv).size()
      n += c.KeyInfo.size()
   }
   if c.Manufacturer != nil {
      n += c.Manufacturer.size()
   }
   n1 := n
   n1 += new(Ftlv).size()
   n1 += c.Signature.size()
   return uint32(n), uint32(n1)
}

type ContentKey struct {
   KeyId      [16]byte
   KeyType    uint16
   CipherType uint16
   Length     uint16
   Value      []byte
}

// decode decodes a byte slice into a ContentKey structure.
func (c *ContentKey) decode(data []byte) {
   n := copy(c.KeyId[:], data)
   data = data[n:]
   c.KeyType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.CipherType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.Value = data
}

func (l *License) decode(data []byte) error {
   n := copy(l.Magic[:], data)
   data = data[n:]
   l.Offset = binary.BigEndian.Uint16(data)
   data = data[2:]
   l.Version = binary.BigEndian.Uint16(data)
   data = data[2:]
   n = copy(l.RightsId[:], data)
   data = data[n:]
   var value1 Ftlv
   _, err := value1.decode(data) // Type 1
   if err != nil {
      return err
   }
   for len(value1.Value) >= 1 {
      var value2 Ftlv
      n, err = value2.decode(value1.Value)
      if err != nil {
         return err
      }
      value1.Value = value1.Value[n:]
      switch xmrType(value2.Type) {
      case globalPolicyContainerEntryType: // 2
         // Rakuten
      case playbackPolicyContainerEntryType: // 4
         // Rakuten
      case keyMaterialContainerEntryType: // 9
         for len(value2.Value) >= 1 {
            var value3 Ftlv
            n, err = value3.decode(value2.Value)
            if err != nil {
               return err
            }
            value2.Value = value2.Value[n:]
            switch xmrType(value3.Type) {
            case contentKeyEntryType: // 10
               l.ContentKey = &ContentKey{}
               l.ContentKey.decode(value3.Value)
            case deviceKeyEntryType: // 42
               l.EccKey = &EccKey{}
               l.EccKey.decode(value3.Value)
            case auxKeyEntryType: // 81
               l.AuxKeys = &AuxKeys{}
               l.AuxKeys.decode(value3.Value)
            default:
               return errors.New("Ftlv.type")
            }
         }
      case signatureEntryType: // 11
         l.Signature = &LicenseSignature{}
         l.Signature.decode(value2.Value)
      default:
         return errors.New("Ftlv.type")
      }
   }
   return nil
}

type License struct {
   Magic      [4]byte           // 0
   Offset     uint16            // 1
   Version    uint16            // 2
   RightsId   [16]byte          // 3
   ContentKey *ContentKey       // 4.9.10
   EccKey     *EccKey           // 4.9.42
   AuxKeys    *AuxKeys          // 4.9.81
   Signature  *LicenseSignature // 4.11
}

func (c *ContentKey) decrypt(privK *big.Int, aux *AuxKeys) (*xCoord, error) {
   switch c.CipherType {
   case 3:
      decrypt, err := elGamalDecrypt(c.Value, privK)
      if err != nil {
         return nil, err
      }
      var coord xCoord
      coord.New(decrypt.X)
      return &coord, nil
   case 6:
      return c.scalable(privK, aux)
   }
   return nil, errors.New("cannot decrypt key")
}
