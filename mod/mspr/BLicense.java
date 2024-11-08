/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS    */
/* OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,*/
/* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL    */
/* SECURITY EXPLORATIONS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, */
/* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF  */
/* OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE     */
/* SOFTWARE.                                                                  */

package mod.mspr;

import agsecres.tool.*;
import agsecres.helper.*;
import java.lang.*;
import java.util.*;
import java.io.*;

public class BLicense {
   public static final int MAGIC_XMR = 0x584d5200;

   public static final int ATTR_HDR_SIZE = 8;

   public static final short TAG_OuterContainer = 0x0001;  // 1
   public static final short TAG_GlobalPolicy = 0x0002;  // 2
   public static final short TAG_PlaybackPolicy = 0x0004;  // 4
   public static final short TAG_PlayEnabler = 0x0036;  // 54
   public static final short TAG_PlayEnablerType = 0x0039;  // 57
   public static final short TAG_DomainRestriction = 0x0029;  // 41
   public static final short TAG_IssueDate = 0x0013;  // 19
   public static final short TAG_RevInfoVersion = 0x0032;  // 50
   public static final short TAG_SecurityLevel = 0x0034;  // 52
   public static final short TAG_EmbeddedLicenseSettings = 0x0033;  // 51
   public static final short TAG_KeyMaterialContainer = 0x0009;  // 9
   public static final short TAG_ContentKey = 0x000A;  // 10
   public static final short TAG_ECCKey = 0x002A;  // 42
   public static final short TAG_XMRSignature = 0x000B;  // 11
   public static final short TAG_RightsSettingObject = 0x000D;  // 13
   public static final short TAG_OutputProtectionLevelRestriction = 0x0005;  // 5
   public static final short TAG_ExpirationRestriction = 0x0012;  // 18
   public static final short TAG_RealTimeExpirationRestriction = 0x0055;  // 85
   public static final short TAG_UplinkKIDObject = 0x003B;  // 59
   public static final short TAG_ExplicitDigitalVideoOutputProtection = 0x0058;  // 88
   public static final short TAG_DigitalVideoOutputRestriction = 0x0059;  // 89
   public static final short TAG_ExplicitDigitalAudioOutputProtection = 0x002E;  // 46
   public static final short TAG_DigitalAudioOutputRestriction = 0x0031;  // 49
   public static final short TAG_SecureStopRestriction = 0x005A;  // 90
   public static final short TAG_ExpirationAfterFirstPlayRestriction = 0x0030;  // 48
   public static final short TAG_RemovalDateObject = 0x0050;  // 80
   public static final short TAG_GracePeriodObject = 0x001A;  // 26
   public static final short TAG_SourceIdObject = 0x0022;  // 34
   public static final short TAG_MeteringRestrictionObject = 0x0016;  // 22
   public static final short TAG_PolicyMetadataObject = 0x002C;  // 44
   public static final short TAG_ExplicitAnalogVideoOutputProtectionContainer = 0x0007;  // 7
   public static final short TAG_AnalogVideoOutputConfigurationRestriction = 0x0008;  // 8
   public static final short TAG_AuxiliaryKeyObject = 0x0051;  // 81
   public static final short TAG_UplinkKeyObject3 = 0x0052;  // 82
   public static final short TAG_CopyObject = 0x003C;  // 60
   public static final short TAG_CopyEnablerContainerObject = 0x0038;  // 56
   public static final short TAG_CopyEnablerObject = 0x003A;  // 58
   public static final short TAG_CopyCountRestrictionObject = 0x003D;  // 61
   public static final short TAG_MoveObject = 0x0037;  // 55
   public static final short TAG_ReadContainerObject = 0x0041;  // 65
   public static final short TAG_ExecuteContainerObject = 0x003F;  // 63
   public static final short TAG_RestrictedSourceIdObject = 0x0028;  // 40

   public static final short TAG_ROOT_CONTAINER = 0x7fff;

   static String tag_name(short tag) {
      switch (tag) {
        case TAG_OuterContainer:
             return "OuterContainer";
        case TAG_GlobalPolicy:
             return "GlobalPolicy";
        case TAG_PlaybackPolicy:
             return "PlaybackPolicy";
        case TAG_PlayEnabler:
             return "PlayEnabler";
        case TAG_PlayEnablerType:
             return "PlayEnablerType";
        case TAG_DomainRestriction:
             return "DomainRestriction";
        case TAG_IssueDate:
             return "IssueDate";
        case TAG_RevInfoVersion:
             return "RevInfoVersion";
        case TAG_SecurityLevel:
             return "SecurityLevel";
        case TAG_EmbeddedLicenseSettings:
             return "EmbeddedLicenseSettings";
        case TAG_KeyMaterialContainer:
             return "KeyMaterialContainer";
        case TAG_ContentKey:
             return "ContentKey";
        case TAG_ECCKey:
             return "ECCKey";
        case TAG_XMRSignature:
             return "XMRSignature";
        case TAG_RightsSettingObject:
             return "RightsSettingObject";
        case TAG_OutputProtectionLevelRestriction:
             return "OutputProtectionLevelRestriction";
        case TAG_ExpirationRestriction:
             return "ExpirationRestriction";
        case TAG_RealTimeExpirationRestriction:
             return "RealTimeExpirationRestriction";
        case TAG_UplinkKIDObject:
             return "UplinkKIDObject";
        case TAG_ExplicitDigitalVideoOutputProtection:
             return "ExplicitDigitalVideoOutputProtection";
        case TAG_DigitalVideoOutputRestriction:
             return "DigitalVideoOutputRestriction";
        case TAG_ExplicitDigitalAudioOutputProtection:
             return "ExplicitDigitalAudioOutputProtection";
        case TAG_DigitalAudioOutputRestriction:
             return "DigitalAudioOutputRestriction";
        case TAG_SecureStopRestriction:
             return "SecureStopRestriction";
        case TAG_ExpirationAfterFirstPlayRestriction:
             return "ExpirationAfterFirstPlayRestriction";
        case TAG_RemovalDateObject:
             return "RemovalDateObject";
        case TAG_GracePeriodObject:
             return "GracePeriodObject";
        case TAG_SourceIdObject:
             return "SourceIdObject";
        case TAG_MeteringRestrictionObject:
             return "MeteringRestrictionObject";
        case TAG_PolicyMetadataObject:
             return "PolicyMetadataObject";
        case TAG_ExplicitAnalogVideoOutputProtectionContainer:
             return "ExplicitAnalogVideoOutputProtectionContainer";
        case TAG_AnalogVideoOutputConfigurationRestriction:
             return "AnalogVideoOutputConfigurationRestriction";
        case TAG_AuxiliaryKeyObject:
             return "AuxiliaryKeyObject";
        case TAG_UplinkKeyObject3:
             return "UplinkKeyObject3";
        case TAG_CopyObject:
             return "CopyObject";
        case TAG_CopyEnablerContainerObject:
             return "CopyEnablerContainerObject";
        case TAG_CopyEnablerObject:
             return "CopyEnablerObject";
        case TAG_CopyCountRestrictionObject:
             return "CopyCountRestrictionObject";
        case TAG_MoveObject:
             return "MoveObject";
        case TAG_ReadContainerObject:
             return "ReadContainerObject";
        case TAG_ExecuteContainerObject:
             return "ExecuteContainerObject";
        case TAG_RestrictedSourceIdObject:
             return "RestrictedSourceIdObject";
      }

      return "Unknown";
   }

   public static Vector < Attr > read_attributes(byte data[]) {
      Vector < Attr > attributes = new Vector < Attr > ();

      ByteInput bi = new ByteInput(data);

      int len = data.length;

      while (len > 0) {
         bi.skip(2);

         short tag = bi.peek_2();

         bi.skip(-2);

         Attr attr = new Attr(bi);
         attributes.add(attr);

         len -= attr.len() + ATTR_HDR_SIZE;
      }

      return attributes;
   }

   public static class Attr {
      String name;
      short lvl;
      short tag;
      int len;
      byte data[];

      public Attr(ByteInput bi) {
         lvl = bi.read_2();
         tag = bi.read_2();
         len = bi.read_4();
         data = bi.read_n(len - 8);

         name = tag_name(tag);
      }

      public Attr(int len, short tag, byte data[]) {
         this.len = len;
         this.tag = tag;
         this.data = data;

         name = tag_name(tag);
      }

      public String name() {
         return name;
      }

      public short lvl() {
         return lvl;
      }

      public short tag() {
         return tag;
      }

      public int len() {
         return len;
      }

      public byte[] data() {
         return data;
      }

      public static Attr parse(Attr attr) {
         switch (attr.tag()) {
         case TAG_OuterContainer:
         case TAG_KeyMaterialContainer:
         case TAG_ExplicitAnalogVideoOutputProtectionContainer:
            return ContainerAttr.get(attr.tag(), attr.data());
         case TAG_SecurityLevel:
            return SecurityLevel.get(attr.data());
         case TAG_ContentKey:
            return ContentKey.get(attr.data());
         case TAG_ECCKey:
         case TAG_XMRSignature:
         case TAG_RightsSettingObject:
         case TAG_OutputProtectionLevelRestriction:
         case TAG_ExpirationRestriction:
         case TAG_RealTimeExpirationRestriction:
         case TAG_UplinkKIDObject:
         case TAG_ExplicitDigitalVideoOutputProtection:
         case TAG_DigitalVideoOutputRestriction:
         case TAG_ExplicitDigitalAudioOutputProtection:
         case TAG_DigitalAudioOutputRestriction:
         case TAG_SecureStopRestriction:
         case TAG_ExpirationAfterFirstPlayRestriction:
         case TAG_RemovalDateObject:
         case TAG_GracePeriodObject:
         case TAG_SourceIdObject:
         case TAG_MeteringRestrictionObject:
         case TAG_PolicyMetadataObject:
         case TAG_AnalogVideoOutputConfigurationRestriction:
         case TAG_AuxiliaryKeyObject:
         case TAG_UplinkKeyObject3:
         case TAG_CopyObject:
         case TAG_CopyEnablerContainerObject:
         case TAG_CopyEnablerObject:
         case TAG_CopyCountRestrictionObject:
         case TAG_MoveObject:
         case TAG_ReadContainerObject:
         case TAG_ExecuteContainerObject:
         case TAG_RestrictedSourceIdObject:
         case TAG_GlobalPolicy:
         case TAG_PlaybackPolicy:
         case TAG_PlayEnabler:
         case TAG_PlayEnablerType:
         case TAG_DomainRestriction:
         case TAG_IssueDate:
         case TAG_RevInfoVersion:
         case TAG_EmbeddedLicenseSettings:
            break;
         }

         return attr;
      }

      public void print() {
         PaddedPrinter pp = Shell.get_pp();
         pp.println("attr: " + Utils.hex_value(tag, 4) + " " + name);
         if (data != null) {
            pp.printhex("data", data());
         }
      }
   }

   public static class SecurityLevel extends Attr {
      short security_level;

      public SecurityLevel(int len, short tag, byte data[]) {
         super(len, tag, data);

         ByteInput bi = new ByteInput(data);

         security_level = bi.read_2();
      }

      public static SecurityLevel get(byte data[]) {
         return new SecurityLevel(data.length, TAG_SecurityLevel, data);
      }

      public void print() {
         PaddedPrinter pp = Shell.get_pp();

         pp.println("SecurityLevel");
         pp.pad(2, "");
         pp.println("level: " + MSPR.SL2string(security_level));
         pp.leave();
      }
   }

   public static class ContentKey extends Attr {
      byte key_id[];
      short v1;
      short v2;
      short enc_data_len;
      byte enc_data[];

      public ContentKey(int len, short tag, byte data[]) {
         super(len, tag, data);

         ByteInput bi = new ByteInput(data);

         key_id = bi.read_n(0x10);
         v1 = bi.read_2();
         v2 = bi.read_2();
         enc_data_len = bi.read_2();
         enc_data = bi.read_n(enc_data_len);
      }

      public byte[] key_id() {
         return key_id;
      }

      public byte[] enc_data() {
         return enc_data;
      }

      public static ContentKey get(byte data[]) {
         return new ContentKey(data.length, TAG_ContentKey, data);
      }

      public void print() {
         PaddedPrinter pp = Shell.get_pp();

         pp.println("ContentKey");
         pp.pad(2, "");
         pp.printhex("key_id", key_id);
         pp.println("v1:           " + v1);
         pp.println("v2:           " + v2);
         pp.println("enc_data_len: " + Utils.hex_value(enc_data_len, 4));
         pp.printhex("enc_data", enc_data);
         pp.leave();
      }
   }

   public static class ContainerAttr extends Attr {
      Vector < Attr > attributes;

      public ContainerAttr(int len, short tag, byte data[]) {
         super(len, tag, data);

         this.attributes = new Vector < Attr > ();
      }

      public ContainerAttr(int len, short tag, byte data[], Vector < Attr > attributes) {
         super(len, tag, data);

         this.attributes = attributes;
      }

      public int cnt() {
         return attributes.size();
      }

      public Attr get(int i) {
         if (i < cnt()) {
            return attributes.elementAt(i);
         }

         return null;
      }

      public void add_attr(Attr a) {
         attributes.add(a);
      }

      public Attr lookup_attr_by_name(String name) {
         for (int i = 0; i < cnt(); i++) {
            Attr attr = get(i);
            System.out.println(attr.name());
            if (attr.name().equals(name)) {
               return attr;
            }
         }
         return null;
      }

      public static Attr read_attr(byte data[]) {
         return read_attributes(data).elementAt(0);
      }

      public static Attr get(short tag, byte data[]) {
         Vector < Attr > attributes = read_attributes(data);

         if (attributes.size() > 0) {
            if ((attributes.size() == 1) && (tag != TAG_ROOT_CONTAINER)) {
               return Attr.parse(attributes.elementAt(0));
            } else {
               Vector < Attr > new_attributes = new Vector < Attr > ();

               int len = data.length;

               ContainerAttr container = new ContainerAttr(len, tag, data, new_attributes);

               for (int i = 0; i < attributes.size(); i++) {
                  Attr attr = attributes.elementAt(i);
                  Attr new_attr = Attr.parse(attr);

                  new_attributes.add(new_attr);
               }

               return container;
            }
         }

         return null;
      }

      public void print() {
         PaddedPrinter pp = Shell.get_pp();

         if (tag != TAG_ROOT_CONTAINER) {
            pp.println("attr: " + Utils.hex_value(tag, 4) + " " + name);
         }

         pp.pad(2, "");

         for (int i = 0; i < attributes.size(); i++) {
            Attr attr = attributes.elementAt(i);

            attr.print();
         }

         pp.leave();
      }
   }

   byte data[];

   int version;
   byte unknown_data[];

   ContainerAttr root;

   public BLicense(byte data[]) {
      this.data = data;

      ByteInput bi = new ByteInput(data);

      int magic = bi.read_4();

      if (magic == MAGIC_XMR) {
         this.version = bi.read_4();
         this.unknown_data = bi.read_n(0x10);

         this.root = (ContainerAttr) ContainerAttr.get(TAG_ROOT_CONTAINER, bi.remaining_data());
      }
   }

   public static String[] tokenize_path(String path) {
      return Utils.tokenize(path, ".");
   }

   public Attr get_attr(String attrpath) {
      String path_elem[] = tokenize_path(attrpath);

      Attr curpos = root;
      Attr res = null;

      for (int i = 0; i < path_elem.length; i++) {
         if (curpos instanceof ContainerAttr) {
            res = ((ContainerAttr) curpos).lookup_attr_by_name(path_elem[i]);
            System.out.println("---");
         }

         if (res == null) break;

         curpos = res;
      }

      return res;
   }

   public void print() {
      PaddedPrinter pp = Shell.get_pp();

      pp.println("XMR LICENSE");

      pp.pad(1, "");
      pp.println("version: " + version);
      root.print();
      pp.leave();
   }
}
