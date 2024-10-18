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
import java.math.*;

public abstract class BCert {
 public static final String BASE_DIR   = "secrets";

 //magic binary cert file types
 public static final int BCERT_CHAIN   = 0x43484149;
 public static final int BCERT_CERT    = 0x43455254;

 //recognized cert attributes
 public static final int TAG_IDS       = 0x00010001;
 public static final int TAG_KEYINFO   = 0x00010006;
 public static final int TAG_SIGNATURE = 0x00010008;
 public static final int TAG_NAMES     = 0x00000007;

 //key tag ?
 public static final int TAG_KEY       = 0x00010200;

 //key types
 public static final int KEY_SIGNING     = 0x0;
 public static final int KEY_ENCRYPTION  = 0x1;

 //lengths
 public static final int DIGEST_SIZE    = 0x20;
 public static final int SIGNATURE_SIZE = 0x40;
 public static final int PUB_KEY_SIZE   = 0x40;

 public static final int BO_SIZE        = 0x400;
 
 String source;

 public static byte[] load_file(String name) {
  String path=BASE_DIR+File.separatorChar+name;

  return Utils.load_file(path);
 }

 public boolean save_file(String name,byte data[]) {
  String path=BASE_DIR+File.separatorChar+name;

  return Utils.save_file(path,data);
 }

 public static BCert from_file(String name) {
  byte data[]=load_file(name);

  if (data!=null) {
   ByteInput bi=new ByteInput(name,data);

   int magic=bi.peek_4();

   switch(magic) {
    case BCERT_CHAIN:
     return new CertificateChain(bi);
    case BCERT_CERT:
     return new Certificate(bi);
   }
  }

  //unknown bcert file
  return null;
 }

 public static class CertAttr {
  int tag;
  int len;
  byte data[];
  int pos;

  public CertAttr(ByteInput bi,int pos) {
   this.pos=pos;

   tag=bi.read_4();
   len=bi.read_4();

   pos+=8;

   data=bi.read_n(len-8);
  }

  public int tag() {
   return tag;
  }

  public int len() {
   return len;
  }

  public byte[] data() {
   return data;
  }

  public int pos() {
   return pos;
  }

 }

 public static class CertificateChain extends BCert {
  int magic;
  int word1;
  int total_len;
  int word3;
  int cert_cnt;
  Vector<Certificate> certs;

  public CertificateChain() {
   super(null);

   certs=new Vector<Certificate>();
  }

  public CertificateChain(ByteInput bi) {
   super(bi.source());

   magic=bi.read_4();
   word1=bi.read_4();
   total_len=bi.read_4();
   word3=bi.read_4();
   cert_cnt=bi.read_4();

   certs=new Vector<Certificate>();

   for(int i=0;i<cert_cnt;i++) {
    Certificate cert=new Certificate(bi);
    certs.add(cert);
   }
  }

  public int cert_cnt() {
   return cert_cnt;
  }

  public Certificate get(int idx) {
   Certificate res=null;

   if (idx<certs.size()) return certs.elementAt(idx);

   return res;
  }

  public void add(Certificate cert) {
   certs.add(cert);
   cert_cnt++;
  }

  public CertificateChain insert(Certificate cert) {
   CertificateChain chain=new CertificateChain();

   chain.add(cert);

   for(int i=0;i<certs.size();i++) {
    chain.add(certs.get(i));
   }

   return chain;
  }

  public void print(boolean debug) {
   for(int i=0;i<cert_cnt;i++) {
    Certificate cert=certs.elementAt(i);

    cert.print();
   }
  }

  public byte[] body() {
   ByteOutput bo=new ByteOutput(BO_SIZE);

   int total_len=0;

   for(int i=0;i<cert_cnt;i++) {
    Certificate cert=certs.elementAt(i);

    total_len+=cert.body().length;
   }

   total_len+=5*4;

   bo.write_4(BCERT_CHAIN);
   bo.write_4(0x00000001);
   bo.write_4(total_len);
   bo.write_4(0x00000000);
   bo.write_4(cert_cnt);

   for(int i=0;i<cert_cnt;i++) {
    Certificate cert=certs.elementAt(i);

    byte cert_data[]=cert.body();

    bo.write_n(cert_data);
   }

   return bo.bytes();
  }
 }

 public static class Certificate extends BCert {
  int magic;
  int word1;
  int total_len;
  int cert_len;
  Vector<CertAttr> attributes;
  byte data[];

  //unpacked cert attributes
  String names[];
  byte random[];
  int seclevel;
  byte digest[];
  byte uniqueid[];
  byte pubkey_sign[];
  byte pubkey_enc[];
  byte signature[];
  byte signing_key[];

  byte prvkey_sign[];
  
  public Certificate() {
   super(null);

   attributes=new Vector<CertAttr>();
  }

  public Certificate(ByteInput bi) {
   super(bi.source());

   int start_pos=bi.get_pos();

   magic=bi.read_4();
   word1=bi.read_4();
   total_len=bi.read_4();
   cert_len=bi.read_4();

   attributes=new Vector<CertAttr>();

   int len=total_len-0x10;

   while(len>0) {
    CertAttr attr=new CertAttr(bi,bi.get_pos()-start_pos);
    attributes.add(attr);

    len-=attr.len();    
   }

   int end_pos=bi.get_pos();

   int n=end_pos-start_pos;

   bi.set_pos(start_pos);
   data=bi.read_n(n);
  }

  public void verify_signing_key() {
   if ((prvkey_sign!=null)&&(pubkey_sign!=null)) {
    BigInteger k=ECC.make_bi(prvkey_sign,0,0x20);

    ECC.ECPoint pub=new ECC.ECPoint(pubkey_sign);
    ECC.ECPoint genpoint=ECC.GEN().op_multiply(k);

    if (!ECC.on_curve(genpoint)) ERR.log("Device cert signing key not on curve");
    if (!genpoint.equals(pub)) ERR.log("Device cert prv signing key does not match public key");
   }
  }

  public void set_names(String names[]) {
   this.names=names;
  }

  public void set_random(byte random[]) {
   this.random=random;
  }

  public void set_seclevel(int seclevel) {
   this.seclevel=seclevel;
  }

  public void set_digest(byte digest[]) {
   this.digest=digest;
  }

  public void set_uniqueid(byte uniqueid[]) {
   this.uniqueid=uniqueid;
  }

  public void set_prvkey_sign(byte prvkey_sign[]) {
   this.prvkey_sign=prvkey_sign;

   verify_signing_key();
  }

  public void set_pubkey_sign(byte pubkey_sign[]) {
   this.pubkey_sign=pubkey_sign;

   verify_signing_key();
  }

  public void set_pubkey_enc(byte pubkey_enc[]) {
   this.pubkey_enc=pubkey_enc;
  }

  public void set_signature(byte signature[]) {
   this.signature=signature;
  }

  public void set_signing_key(byte signing_key[]) {
   this.signing_key=signing_key;
  }
 
  public byte[] read_data(int tag,int off,int len) {
   byte res[]=null;

   CertAttr attr=lookup_tag(tag);

   if (attr!=null) {
    byte data[]=attr.data();

    ByteInput bi=new ByteInput(data);
    bi.set_pos(off);

    return bi.read_n(len);
   }

   return res;
  }

  public String[] get_names() {
   if ((source!=null)&&(names==null)) {
    String res[]=new String[0];

    CertAttr attr=lookup_tag(TAG_NAMES);

    if (attr!=null) {
     Vector<String> vstr=new Vector<String>();

     byte data[]=attr.data();
     int len=data.length;

     ByteInput bi=new ByteInput(data);

     while(len>0) {
      int size=bi.read_4();

      if (size>0) {
       size=(size+3)&0xfffffffc;

       String s=bi.read_string(size);
       vstr.add(s);

       len-=size;
      }

      len-=4;
     }

     res=new String[vstr.size()];

     for(int i=0;i<vstr.size();i++) {
      res[i]=vstr.elementAt(i);
     }

     names=res;
    }
   }

   return names;
  }

  public byte[] get_random() {
   if ((source!=null)&&(random==null)) {
    random=read_data(TAG_IDS,0,0x10);
   }

   return random;
  }

  public int get_seclevel() {
   if ((source!=null)&&(seclevel==0)) {
    CertAttr attr=lookup_tag(TAG_IDS);

    if (attr!=null) {
     byte data[]=attr.data();

     ByteInput bi=new ByteInput(data);
     bi.set_pos(0x10);

     seclevel=bi.read_4();
    }
   }

   return seclevel;
  }

  public byte[] get_digest() {
   if ((source!=null)&&(digest==null)) {
    digest=read_data(TAG_IDS,0x1c,DIGEST_SIZE);
   }

   if (source==null) {
    //calc digest of public key
    byte pubkey[]=get_pubkey_for_signing();
    digest=Crypto.SHA256(pubkey);
   }

   return digest;
  }

  public byte[] get_uniqueid() {
   if ((source!=null)&&(uniqueid==null)) {
    uniqueid=read_data(TAG_IDS,0x40,0x10);
   }

   return uniqueid;
  }

  public byte[] get_pubkey(int keyidx) {
   byte res[]=null;

   CertAttr attr=lookup_tag(TAG_KEYINFO);

   if (attr!=null) {
    byte data[]=attr.data();
    int len=data.length;

    ByteInput bi=new ByteInput(data);
    int keycnt=bi.read_4();

    if (keyidx<keycnt) {
     int keysize=0x50;
     bi.skip(keyidx*keysize);

     int tag=bi.read_4();

     if (tag==TAG_KEY) {
      bi.skip(4);
      res=bi.read_n(PUB_KEY_SIZE);
     }
    }
   }

   return res;
  }

  public int get_pubkey_pos(int keyidx) {
   CertAttr attr=lookup_tag(TAG_KEYINFO);

   if (attr!=null) {
    int pos=attr.pos();

    byte data[]=attr.data();
    int len=data.length;

    ByteInput bi=new ByteInput(data);
    int keycnt=bi.read_4();
    pos+=4;

    if (keyidx<keycnt) {
     int keysize=0x50;
     bi.skip(keyidx*keysize);
     pos+=keyidx*keysize;

     int tag=bi.read_4();
     pos+=4;

     if (tag==TAG_KEY) {
      bi.skip(4);
      pos+=4;
      return pos;
     }
    }
   }

   return -1;
  }

  public int get_digest_pos() {
   CertAttr attr=lookup_tag(TAG_IDS);

   return attr.pos+0x1c;
  }

  public byte[] get_prvkey_for_signing() {
   return prvkey_sign;
  }

  public byte[] get_pubkey_for_signing() {
   if ((source!=null)&&(pubkey_sign==null)) {
    pubkey_sign=get_pubkey(KEY_SIGNING);
   }

   return pubkey_sign;
  }

  public byte[] get_pubkey_for_encryption() {
   if ((source!=null)&&(pubkey_enc==null)) {
    pubkey_enc=get_pubkey(KEY_ENCRYPTION);
   }

   return pubkey_enc;
  }

  public byte[] get_signature() {
   if ((source!=null)&&(signature==null)) {
    signature=read_data(TAG_SIGNATURE,0x04,SIGNATURE_SIZE);
   }

   return signature;
  }

  public int get_signature_pos() {
   CertAttr attr=lookup_tag(TAG_SIGNATURE);

   return attr.pos+0x04;
  }

  public byte[] get_signkey() {
   if ((source!=null)&&(signing_key==null)) {
    signing_key=read_data(TAG_SIGNATURE,0x04+SIGNATURE_SIZE+0x04,PUB_KEY_SIZE);
   }

   if (signing_key==null) {
    return Device.get_group_pubkey().bytes();
   }

   return signing_key;
  }

  public int get_signkey_pos() {
   CertAttr attr=lookup_tag(TAG_SIGNATURE);

   return attr.pos+0x04+SIGNATURE_SIZE+0x04;
  }

  public boolean verify_signature() {
   byte signature[]=get_signature();
   ECC.ECSignature ecsig=new ECC.ECSignature(signature);

   byte signkey[]=get_signkey();
   ECC.ECPoint pubkey=new ECC.ECPoint(signkey);

   byte signed_data[]=get_signed_data();
   byte digest[]=Crypto.SHA256(signed_data);

   return ecsig.verify(digest,pubkey);
  }

  //sign cert data with the use of a given (possibly fake) EC key
  public void sign(ECC.ECKey root_signing_key,ECC.ECKey cert_signing_key) {
   //set new signing key defined by this cert (pubkey_sign)
   int pubkey_pos=get_pubkey_pos(KEY_SIGNING)+8;
   pubkey_sign=cert_signing_key.pub().bytes();
   System.arraycopy(pubkey_sign,0,data,pubkey_pos,pubkey_sign.length);

   //calc and set new digest (hash of pubkey_sign)
   int digest_pos=get_digest_pos()+8;
   digest=Crypto.SHA256(pubkey_sign);
   System.arraycopy(digest,0,data,digest_pos,digest.length);

   byte signed_data[]=get_signed_data();
   byte digest[]=Crypto.SHA256(signed_data);

   //calc and set new signature
   ECC.ECSignature ecsig=ECC.ECSignature.get(digest,root_signing_key.prv());
   signature=ecsig.bytes();

   int signature_pos=get_signature_pos()+8;
   System.arraycopy(signature,0,data,signature_pos,signature.length);

   //set new root signing key (required for signature verification)
   signing_key=root_signing_key.pub().bytes();
   int signkey_pos=get_signkey_pos()+8;
   System.arraycopy(signing_key,0,data,signkey_pos,signing_key.length);
  }

  public void print(boolean debug) {
   String names[]=get_names();

   byte random[]=get_random();
   
   byte uniqueid[]=get_uniqueid();

   byte pubkey_sign[]=get_pubkey_for_signing();
  
   byte pubkey_enc[]=get_pubkey_for_encryption();

   byte digest[]=get_digest();
   
   byte signature[]=get_signature();

   byte signkey[]=get_signkey();

   if ((signature!=null)&&(signkey!=null)) {
    boolean status=verify_signature();

    String sig_status="sig status: ";

    if (status) sig_status+="OK";
     else sig_status+="BAD SIGNATURE";
   
   }

  }

  public CertAttr lookup_tag(int tag) {
   for(int i=0;i<attributes.size();i++) {
    CertAttr attr=attributes.elementAt(i);

    if (attr.tag()==tag) return attr;
   }

   return null;
  }

  public byte[] get_signed_data() {
   if (data!=null) {
    byte signed_data[]=new byte[data.length-2*0x40-0x10];

    System.arraycopy(data,0,signed_data,0,signed_data.length);

    return signed_data;
   }

   ByteOutput bo=new ByteOutput(BO_SIZE);
   bo.write_4(BCERT_CERT);
   bo.write_4(0x00000001);

   int cert_len_pos=bo.get_pos();
   bo.skip(4);

   int cert_len_no_sig_pos=bo.get_pos();
   bo.skip(4);

   //ids
   bo.write_4(TAG_IDS);
   //fixed len
   bo.write_4(0x58);

   byte random[]=get_random();
   if (random==null) ERR.log("missing random attr for BCert");
   bo.write_n(random);

   int seclevel=get_seclevel();
   if (seclevel==0) ERR.log("missing security level attr for BCert");
   bo.write_4(seclevel);

   bo.write_4(0x00000000);
   bo.write_4(0x00000002);

   digest=get_digest();
   if (digest==null) ERR.log("cannot evaulate digest attr for BCert");
   bo.write_n(digest);

   bo.write_4(0xffffffff);

   byte id[]=get_uniqueid();
   if (id==null) ERR.log("missing uniqueid attr for BCert");
   bo.write_n(id);
  
   //unknown tag
   bo.write_4(0x00010004);
   //fixed len
   bo.write_4(0x14);

   bo.write_4(0x00002800);
   bo.write_4(0x00003C00);
   bo.write_4(0x00000002);

   //unknown tag
   bo.write_4(0x00010005);
   //fixed len
   bo.write_4(0x10);

   bo.write_4(0x00000001);
   bo.write_4(0x00000004);

   //keys
   bo.write_4(TAG_KEYINFO);
   //fixed len
   bo.write_4(0xac);

   //key cnt ?
   bo.write_4(0x00000002);

   bo.write_4(0x00010200);
   bo.write_4(0x00000000);

   byte pubkey_sign[]=get_pubkey_for_signing();
   if (pubkey_sign==null) ERR.log("missing public key for signing attr in BCert");
   bo.write_n(pubkey_sign);
   bo.write_4(0x00000001);
   bo.write_4(0x00000001);

   bo.write_4(0x00010200);
   bo.write_4(0x00000000);

   byte pubkey_enc[]=get_pubkey_for_encryption();
   if (pubkey_enc==null) ERR.log("missing public key for encryption attr in BCert");
   bo.write_n(pubkey_enc);
   bo.write_4(0x00000001);
   bo.write_4(0x00000002);

   int cur_pos=bo.get_pos();

   int signed_data_len=bo.length();//+8;
   int signature_size=0x90;

   //adjust cert size (total and without signature)
   bo.set_pos(cert_len_pos);
   bo.write_4(signed_data_len+signature_size);

   bo.set_pos(cert_len_no_sig_pos);
   bo.write_4(signed_data_len);

   bo.set_pos(cur_pos);

   byte signed_data[]=bo.bytes();

   return signed_data;
  }

  public byte[] body() {
   if (data!=null) return data;

   ByteOutput bo=new ByteOutput(BO_SIZE);
   bo.write_4(BCERT_CERT);
   bo.write_4(0x00000001);

   int cert_len_pos=bo.get_pos();
   bo.skip(4);

   int cert_len_no_sig_pos=bo.get_pos();
   bo.skip(4);

   //ids
   bo.write_4(TAG_IDS);
   //fixed len
   bo.write_4(0x58);

   byte random[]=get_random();
   if (random==null) ERR.log("missing random attr for BCert");
   bo.write_n(random);

   int seclevel=get_seclevel();
   if (seclevel==0) ERR.log("missing security level attr for BCert");
   bo.write_4(seclevel);

   bo.write_4(0x00000000);
   bo.write_4(0x00000002);

   digest=get_digest();
   if (digest==null) ERR.log("cannot evaulate digest attr for BCert");
   bo.write_n(digest);

   bo.write_4(0xffffffff);

   byte id[]=get_uniqueid();
   if (id==null) ERR.log("missing uniqueid attr for BCert");
   bo.write_n(id);
  
   //unknown tag
   bo.write_4(0x00010004);
   //fixed len
   bo.write_4(0x14);

   bo.write_4(0x00002800);
   bo.write_4(0x00003C00);
   bo.write_4(0x00000002);

   //unknown tag
   bo.write_4(0x00010005);
   //fixed len
   bo.write_4(0x10);

   bo.write_4(0x00000001);
   bo.write_4(0x00000004);

   //keys
   bo.write_4(TAG_KEYINFO);
   //fixed len
   bo.write_4(0xac);

   //key cnt ?
   bo.write_4(0x00000002);

   bo.write_4(0x00010200);
   bo.write_4(0x00000000);

   byte pubkey_sign[]=get_pubkey_for_signing();
   if (pubkey_sign==null) ERR.log("missing public key for signing attr in BCert");
   bo.write_n(pubkey_sign);
   bo.write_4(0x00000001);
   bo.write_4(0x00000001);

   bo.write_4(0x00010200);
   bo.write_4(0x00000000);

   byte pubkey_enc[]=get_pubkey_for_encryption();
   if (pubkey_enc==null) ERR.log("missing public key for encryption attr in BCert");
   bo.write_n(pubkey_enc);
   bo.write_4(0x00000001);
   bo.write_4(0x00000002);

   int cur_pos=bo.get_pos();

   int signed_data_len=bo.length();//+8;
   int signature_size=0x90;

   //adjust cert size (total and without signature)
   bo.set_pos(cert_len_pos);
   bo.write_4(signed_data_len+signature_size);

   bo.set_pos(cert_len_no_sig_pos);
   bo.write_4(signed_data_len);

   bo.set_pos(cur_pos);

   byte signed_data[]=bo.bytes();

   byte signed_digest[]=Crypto.SHA256(signed_data);

   //signature
   bo.write_4(TAG_SIGNATURE);
   //fixed len
   bo.write_4(signature_size);

   bo.write_4(0x00010040);

   ECC.ECSignature ecsig=ECC.ECSignature.get(signed_digest,Device.get_group_prvkey());
   signature=ecsig.bytes();

   bo.write_n(signature);

   //public key
   bo.write_4(0x00000200);

   ECC.ECPoint group_pubkey=Device.get_group_pubkey();
   byte pubkey_data[]=group_pubkey.bytes();
   bo.write_n(pubkey_data);

   data=bo.bytes();

   return data;
  }
 }

 public BCert(String source) {
  this.source=source;
 }

 public boolean save(String name) {
  byte data[]=body();

  return save_file(name,data);
 }

 public abstract void print(boolean debug);
 public abstract byte[] body();

 public void print() {
  print(false);
 }
}
