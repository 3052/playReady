package header

import (
   "41.neocities.org/playReady/license"
   "encoding/base64"
   "encoding/binary"
   "errors"
   "github.com/beevik/etree"
   "golang.org/x/text/encoding/unicode"
   "golang.org/x/text/transform"
   "strings"
)

type PlayReadyObject struct {
   Type   uint16
   Length uint16
   Data   string
}

func (p *PlayReadyObject) Decode(data []byte) bool {
   p.Type = binary.LittleEndian.Uint16(data)
   data = data[2:]
   p.Length = binary.LittleEndian.Uint16(data)
   data = data[2:]

   if int(p.Length) > len(data) {
      return false
   }

   decoder := unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewDecoder()

   decodedStr, _, err := transform.String(decoder, string(data))

   if err != nil {
      return false
   }

   p.Data = decodedStr

   return true
}

type PlayReadyRecord struct {
   Length uint32
   Count  uint16
   Data   []byte
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

func (p *ProtectionSystemHeaderBox) Decode(data []byte) {
   p.Size = binary.BigEndian.Uint32(data)
   data = data[4:]
   n := copy(p.Type[:], data)
   data = data[n:]

   p.Version = data[0]
   data = data[1:]
   n = copy(p.Flags[:], data)
   data = data[n:]

   p.SystemId.Decode(data)

   data = data[16:]

   if p.Version == 1 {
      p.KeyIdCount = binary.BigEndian.Uint32(data)
      data = data[4:]

      p.KeyIds = make([]license.Guid, p.KeyIdCount)

      for i := range p.KeyIdCount {
         var KeyId license.Guid
         KeyId.Decode(data)

         p.KeyIds[i] = KeyId
         data = data[16:]
      }
   }

   p.Length = binary.BigEndian.Uint32(data)
   data = data[4:]

   p.Data = data
}

type WrmHeader struct {
   Version string
   KeyIds  []license.Guid
   Data    *etree.Element
}

func (w *WrmHeader) Decode(Wrm string) error {
   ParsedWrm := etree.NewDocument()
   if err := ParsedWrm.ReadFromString(Wrm); err != nil {
      return err
   }

   version := ParsedWrm.Root().SelectAttrValue("version", "")

   if version == "" {
      return errors.New("invalid wrm header")
   }

   w.Version = version

   var KeyIds []*etree.Element

   switch version {
   case "4.0.0.0":
      KeyIds = ParsedWrm.FindElements("/WRMHEADER/DATA/KID")
   case "4.1.0.0":
      KeyIds = ParsedWrm.FindElements("/WRMHEADER/DATA/PROTECTINFO/KID")
   case "4.2.0.0":
   case "4.3.0.0":
      KeyIds = ParsedWrm.FindElements("/WRMHEADER/DATA/PROTECTINFO/KIDS/*")
   }

   w.KeyIds = make([]license.Guid, len(KeyIds))

   for i, e := range KeyIds {
      var KeyId license.Guid

      if e.Text() != "" {
         err := KeyId.Base64Decode(e.Text())
         if err != nil {
            return err
         }
      } else {
         err := KeyId.Base64Decode(e.SelectAttrValue("VALUE", ""))
         if err != nil {
            return err
         }
      }

      w.KeyIds[i] = KeyId
   }

   w.Data = ParsedWrm.Root()

   return nil
}

type Header struct {
   PSSHBox   *ProtectionSystemHeaderBox
   Record    *PlayReadyRecord
   Object    *PlayReadyObject
   WrmHeader *WrmHeader
}

func (h *Header) Parse(data any) error {
   var decoded []byte

   switch v := data.(type) {
   case []byte:
      decoded = v

   case string:
      if strings.HasPrefix(v, "<WRM") {
         return h.ParseWrm(v)
      }

      strDecoded, err := base64.StdEncoding.DecodeString(v)
      if err != nil {
         return err
      }
      decoded = strDecoded

   default:
      return errors.New("parsed data is not of type string or []byte")
   }

   return h.ParseByte(decoded)
}

func (h *Header) ParseByte(data []byte) error {
   if string(data[4:8]) == "pssh" {
      var box ProtectionSystemHeaderBox
      box.Decode(data)

      h.PSSHBox = &box
   }

   if h.PSSHBox != nil && h.PSSHBox.SystemId.Uuid() != "9a04f079-9840-4286-ab92-e65be0885f95" {
      return errors.New("pssh is not for playready")

   }

   PRRecord := data

   if h.PSSHBox != nil {
      PRRecord = h.PSSHBox.Data
   }

   var record PlayReadyRecord

   ok := record.Decode(PRRecord)

   PRObject := data

   if ok == true {
      h.Record = &record

      PRObject = h.Record.Data
   }

   var Object PlayReadyObject

   ok = Object.Decode(PRObject)
   if ok == false {
      return errors.New("unable to parse pssh")
   }

   h.Object = &Object

   return h.ParseWrm(h.Object.Data)
}

func (h *Header) ParseWrm(Wrm string) error {
   var header WrmHeader

   err := header.Decode(Wrm)

   if err != nil {
      return err
   }

   h.WrmHeader = &header

   return nil
}
