package playReady

import (
   "41.neocities.org/playReady/license"
   "encoding/binary"
   "errors"
   "github.com/beevik/etree"
)

func (w *WrmHeader) Decode(data string) error {
   parsed_wrm := etree.NewDocument()
   if err := parsed_wrm.ReadFromString(data); err != nil {
      return err
   }
   version := parsed_wrm.Root().SelectAttrValue("version", "")
   if version == "" {
      return errors.New("invalid wrm header")
   }
   w.Version = version
   var key_ids []*etree.Element
   switch version {
   case "4.0.0.0":
      key_ids = parsed_wrm.FindElements("/WRMHEADER/DATA/KID")
   case "4.1.0.0":
      key_ids = parsed_wrm.FindElements("/WRMHEADER/DATA/PROTECTINFO/KID")
   case "4.2.0.0":
   case "4.3.0.0":
      key_ids = parsed_wrm.FindElements("/WRMHEADER/DATA/PROTECTINFO/KIDS/*")
   }
   w.KeyIds = make([]license.Guid, len(key_ids))
   for i, element := range key_ids {
      var key_id license.Guid
      if element.Text() != "" {
         err := key_id.Base64Decode(element.Text())
         if err != nil {
            return err
         }
      } else {
         err := key_id.Base64Decode(element.SelectAttrValue("VALUE", ""))
         if err != nil {
            return err
         }
      }
      w.KeyIds[i] = key_id
   }
   w.Data = parsed_wrm.Root()
   return nil
}

type PlayReadyObject struct {
   Type   uint16
   Length uint16
   Data   string
}

type PlayReadyRecord struct {
   Length uint32
   Count  uint16
   Data   []byte
}

type ProtectionSystemHeaderBox struct {
   Size       uint32
   Type       [4]byte
   Version    uint8
   Flags      [3]byte
   SystemId   license.Guid
   KeyIdCount uint32
   KeyIds     []license.Guid
   Length     uint32
   Data       []byte
}

type Header struct {
   PSSHBox   *ProtectionSystemHeaderBox
   Record    *PlayReadyRecord
   Object    *PlayReadyObject
   WrmHeader *WrmHeader
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

type WrmHeader struct {
   Version string
   KeyIds  []license.Guid
   Data    *etree.Element
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
   data = binary.BigEndian.AppendUint32(data, d.MaxLicenseChainDepth)

   return data
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

///

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

type FTLV struct {
   Flags  uint16
   Type   uint16
   Length uint32
   Value  []byte
}

func (f *FTLV) New(Flags, Type int, Value []byte) {
   f.Flags = uint16(Flags)
   f.Type = uint16(Type)
   f.Length = uint32(len(Value) + 8)
   f.Value = Value
}

func (f *FTLV) Encode() []byte {
   var data []byte
   data = binary.BigEndian.AppendUint16(data, f.Flags)
   data = binary.BigEndian.AppendUint16(data, f.Type)
   data = binary.BigEndian.AppendUint32(data, f.Length)

   data = append(data, f.Value...)

   return data
}

func (f *FTLV) Decode(data []byte) (uint32, error) {
   var n uint32 = 0
   f.Flags = binary.BigEndian.Uint16(data[n:])
   n += 2
   f.Type = binary.BigEndian.Uint16(data[n:])
   n += 2
   f.Length = binary.BigEndian.Uint32(data[n:])
   n += 4
   f.Value = data[n:][:f.Length-8]
   n += f.Length - 8

   return n, nil
}
