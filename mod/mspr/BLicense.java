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
 public static final int MAGIC_XMR    = 0x584d5200;

 public static final int ATTR_HDR_SIZE = 8;

 //tag values
 public static final short TAG_OuterContainer        = 0x0001;
 public static final short TAG_PlaybackContainer     = 0x0004;
 public static final short TAG_GlobalContainer       = 0x0002;
 public static final short TAG_DWORD_Versioned       = 0x0032;
 public static final short TAG_SecurityLevel         = 0x0034;
 public static final short TAG_WORD                  = 0x0033;
 public static final short TAG_KeyMaterialContainer  = 0x0009;
 public static final short TAG_ContentKey            = 0x000a;
 public static final short TAG_ECCDeviceKey          = 0x002a;
 public static final short TAG_Signature             = 0x000b;

 public static final short TAG_ROOT_CONTAINER        = 0x7fff;

 static String tag_name(short tag) {
  switch(tag) {
   case TAG_OuterContainer:
    return "OuterContainer";
   case TAG_PlaybackContainer:
    return "PlaybackContainer";
   case TAG_GlobalContainer:
    return "GlobalContainer";
   case TAG_DWORD_Versioned:
    return "DWORD_Versioned";
   case TAG_SecurityLevel:
    return "SecurityLevel";
   case TAG_WORD:
    return "WORD";
   case TAG_KeyMaterialContainer:
    return "KeyMaterialContainer";
   case TAG_ContentKey:
    return "ContentKey";
   case TAG_ECCDeviceKey:
    return "ECCDeviceKey";
   case TAG_Signature:
    return "Signature";
  }

  return "Unknown";
 }

 public static Vector<Attr> read_attributes(byte data[]) {
  Vector<Attr> attributes=new Vector<Attr>();

  ByteInput bi=new ByteInput(data);

  int len=data.length;

  while(len>0) {
   bi.skip(2);

   short tag=bi.peek_2();

   bi.skip(-2);

   Attr attr=new Attr(bi);
   attributes.add(attr);

   len-=attr.len()+ATTR_HDR_SIZE;
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
   lvl=bi.read_2();
   tag=bi.read_2();
   len=bi.read_4();
   data=bi.read_n(len-8);

   name=tag_name(tag);
  }

  public Attr(int len,short tag,byte data[]) {
   this.len=len;
   this.tag=tag;
   this.data=data;

   name=tag_name(tag);
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
   switch(attr.tag()) {
    case TAG_OuterContainer:
    case TAG_PlaybackContainer:
    case TAG_GlobalContainer:
    case TAG_KeyMaterialContainer:
     return ContainerAttr.get(attr.tag(),attr.data());
    case TAG_SecurityLevel:
     return SecurityLevel.get(attr.data());
    case TAG_ContentKey:
     return ContentKey.get(attr.data());
    case TAG_DWORD_Versioned:
    case TAG_WORD:
    case TAG_ECCDeviceKey:
    case TAG_Signature:
     break;
   }

   return attr;
  }

  public void print() {
   PaddedPrinter pp=Shell.get_pp();
   pp.println("attr: "+Utils.hex_value(tag,4)+" "+name);
   if (data!=null) {
    pp.printhex("data",data());
   }
  }
 }

 public static class SecurityLevel extends Attr {
  short security_level;

  public SecurityLevel(int len,short tag,byte data[]) {
   super(len,tag,data);

   ByteInput bi=new ByteInput(data);

   security_level=bi.read_2();
  }

  public static SecurityLevel get(byte data[]) {
   return new SecurityLevel(data.length,TAG_SecurityLevel,data);
  }

  public void print() {
   PaddedPrinter pp=Shell.get_pp();

   pp.println("SecurityLevel");
   pp.pad(2,"");
   pp.println("level: "+MSPR.SL2string(security_level));
   pp.leave();
  }
 }

 public static class ContentKey extends Attr {
  byte key_id[];
  short v1;
  short v2;
  short enc_data_len;
  byte enc_data[];

  public ContentKey(int len,short tag,byte data[]) {
   super(len,tag,data);

   ByteInput bi=new ByteInput(data);

   key_id=bi.read_n(0x10);
   v1=bi.read_2();
   v2=bi.read_2();
   enc_data_len=bi.read_2();

   enc_data=bi.read_n(enc_data_len);
  }

  public byte[] key_id() {
   return key_id;
  }


  public byte[] enc_data() {
   return enc_data;
  }
 
  public static ContentKey get(byte data[]) {
   return new ContentKey(data.length,TAG_ContentKey,data);
  }

  public void print() {
   PaddedPrinter pp=Shell.get_pp();

   pp.println("ContentKey");
   pp.pad(2,"");
   pp.printhex("key_id",key_id);
   pp.println("v1:           "+v1);
   pp.println("v2:           "+v2);
   pp.println("enc_data_len: "+Utils.hex_value(enc_data_len,4));
   pp.printhex("enc_data",enc_data);
   pp.leave();
  }
 }

 public static class ContainerAttr extends Attr {
  Vector<Attr> attributes;

  public ContainerAttr(int len,short tag,byte data[]) {
   super(len,tag,data);

   this.attributes=new Vector<Attr>();
  }

  public ContainerAttr(int len,short tag,byte data[],Vector<Attr> attributes) {
   super(len,tag,data);

   this.attributes=attributes;
  }

  public int cnt() {
   return attributes.size();
  }

  public Attr get(int i) {
   if (i<cnt()) {
    return attributes.elementAt(i);
   }

   return null;
  }

  public void add_attr(Attr a) {
   attributes.add(a);
  }

  public Attr lookup_attr_by_name(String name) {
   for(int i=0;i<cnt();i++) {
    Attr attr=get(i);

    if (attr.name().equals(name)) return attr;
   }

   return null;
  }

  public static Attr read_attr(byte data[]) {
   return read_attributes(data).elementAt(0);
  }

  public static Attr get(short tag,byte data[]) {
   Vector<Attr> attributes=read_attributes(data);

   if (attributes.size()>0) {
    if ((attributes.size()==1)&&(tag!=TAG_ROOT_CONTAINER)) {
     return Attr.parse(attributes.elementAt(0));
    } else {
     Vector<Attr> new_attributes=new Vector<Attr>();

     int len=data.length;

     ContainerAttr container=new ContainerAttr(len,tag,data,new_attributes);

     for(int i=0;i<attributes.size();i++) {
      Attr attr=attributes.elementAt(i);
      Attr new_attr=Attr.parse(attr);

      new_attributes.add(new_attr);
     }

     return container;
    }
   }

   return null;
  }

  public void print() {
   PaddedPrinter pp=Shell.get_pp();

   if (tag!=TAG_ROOT_CONTAINER) {
    pp.println("attr: "+Utils.hex_value(tag,4)+" "+name);
   }

   pp.pad(2,"");

   for(int i=0;i<attributes.size();i++) {
    Attr attr=attributes.elementAt(i);
 
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
  this.data=data;

  ByteInput bi=new ByteInput(data);

  int magic=bi.read_4();

  if (magic==MAGIC_XMR) {
   this.version=bi.read_4();
   this.unknown_data=bi.read_n(0x10);

   this.root=(ContainerAttr)ContainerAttr.get(TAG_ROOT_CONTAINER,bi.remaining_data());
  }
 }

 public static String[] tokenize_path(String path) {
  return Utils.tokenize(path,".");
 }

 public Attr get_attr(String attrpath) {
  String path_elem[]=tokenize_path(attrpath);

  Attr curpos=root;
  Attr res=null;

  for(int i=0;i<path_elem.length;i++) {
   if (curpos instanceof ContainerAttr) {
    res=((ContainerAttr)curpos).lookup_attr_by_name(path_elem[i]);
   }

   if (res==null) break;

   curpos=res;
  }

  return res;
 }

 public void print() {
  PaddedPrinter pp=Shell.get_pp();

  pp.println("XMR LICENSE");

  pp.pad(1,"");
  pp.println("version: "+version);
  root.print();
  pp.leave();
 }
}
