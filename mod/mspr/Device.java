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
import java.io.*;
import java.math.*;

public class Device {
 public static final int DEFAULT_SL = MSPR.SL2000;

 public static final int UNIQUEID_SIZE = 0x10;
 public static final int MAC_SIZE      = 0x06;

 String serial;
 String mac;

 byte[] uniqueid;

 ECC.ECKey sign_key;
 ECC.ECKey enc_key;

 BCert.Certificate cert;
 BCert.CertificateChain cert_chain;

 static BCert.CertificateChain group_cert;

 static ECC.ECKey group_key;

 static Device curdev;

 static {
  group_key=ECC.ECKey.from_file(BCert.BASE_DIR+File.separatorChar+"z1");
 }

 public static int cur_SL() {
  int seclevel=MSPR.string2SL(Vars.get_str("SECLEVEL"));

  if (seclevel<0) {
   seclevel=DEFAULT_SL;
  }

  return seclevel;
 }

 public Device(String serial,String mac) {
  this.serial=serial;
  this.mac=mac;

  if (MSPR.fixed_identity()) {
   this.sign_key=new ECC.ECKey(Utils.parse_hex_string("f105e249363781a7c24ebd0bc1ba66642194f26ef2614998932b9bb67fef1337"));
   this.enc_key=new ECC.ECKey(Utils.parse_hex_string("d59e783a81ec4159a5089bfa735245421d4847eb4376c297112451a35b3e179d"));
  } else {
   this.sign_key=new ECC.ECKey();
   this.enc_key=new ECC.ECKey();
  }
 }

 static String revert_serial(String serial,int revert_pos) {
  int len=serial.length();

  String reverted=serial.substring(0,revert_pos);

  for(int i=len-1;i>=revert_pos;i--) {
   reverted+=serial.charAt(i);
  }

  return reverted;
 }

 public Device(String serial,String mac,byte[] uniqueid) {
  this(serial,mac);

  this.uniqueid=uniqueid;
 }

 public String get_serial() {
  return serial;
 }

 public String get_reverted_serial() {
  return revert_serial(serial,4);
 }

 public String get_mac() {
  return mac;
 }

 private void setup_uniqueid() {
  if (mac.length()!=(2*MAC_SIZE)) ERR.log("Invalid MAC addr length: "+mac.length());
  if (serial.length()<UNIQUEID_SIZE) ERR.log("Invalid SERIAL length: "+serial.length());

  byte serial_bytes[]=serial.getBytes();
  byte mac_bytes[]=Utils.parse_hex_string(mac);

  byte tmp[]=new byte[UNIQUEID_SIZE];
  System.arraycopy(serial_bytes,0,tmp,0,UNIQUEID_SIZE);

  for(int i=0;i<MAC_SIZE;i++) {
   tmp[i]^=mac_bytes[i];
  }

  uniqueid=new byte[UNIQUEID_SIZE];
  
  int pos=0;
  System.arraycopy(tmp,0,uniqueid,pos,4);
  pos+=4;
  
  uniqueid[pos++]='C';

  System.arraycopy(tmp,4,uniqueid,pos,4);
  pos+=4;
  
  uniqueid[pos++]='A';

  System.arraycopy(tmp,8,uniqueid,pos,4);
  pos+=4;
  
  uniqueid[pos++]='D';

  System.arraycopy(tmp,12,uniqueid,pos,1);
 }

 public byte[] get_uniqueid() {
  if (uniqueid==null) {
   setup_uniqueid();
  }

  return uniqueid;
 }

 public ECC.ECKey sign_key() {
  return sign_key;
 }

 public ECC.ECKey enc_key() {
  return enc_key;
 }

 public void print() {
  sign_key.print("sign key");
  enc_key.print("enc key");
 }

 static void gen_fake_group_cert() {
  //generate new root key
  ECC.ECKey root_sign_key=new ECC.ECKey();

  for(int i=group_cert.cert_cnt()-1;i>=0;i--) {
   //process certificates in a backward order
   BCert.Certificate cert=group_cert.get(i);

   //generate cert signing key
   ECC.ECKey cert_sign_key=new ECC.ECKey();

   cert.sign(root_sign_key,cert_sign_key);

   //set cert sign key as new root
   root_sign_key=cert_sign_key;
  }

  //store root sign key as a new group key
  group_key=root_sign_key;  
 }

 public static BCert.CertificateChain get_group_cert() {
  if (group_cert==null) {
   group_cert=(BCert.CertificateChain)BCert.from_file("g1");

   //check if we should generate fake group cert
   if (Vars.get_int("MSPR_FAKE_ROOT")==1) {
    gen_fake_group_cert();

    group_cert.save("fakechain");
   }
  }
  
  return group_cert;
 }

 public static BigInteger get_group_prvkey() {
  return group_key.prv();
 }

 public static ECC.ECPoint get_group_pubkey() {
  return group_key.pub();
 }

 public static boolean changed() {
  String serial=Vars.get_str("SERIAL");
  String mac=Vars.get_str("MAC");

  boolean device_changed=false;

  if (curdev!=null) {
   String curserial=curdev.get_serial();
   String curmac=curdev.get_mac();

   if ((!curserial.equals(serial))||(!curmac.equals(mac))) device_changed=true;
  } else device_changed=true;
  
  return device_changed;
 }

 public BCert.Certificate get_cert() {
  if ((cert==null)||changed()||((cert!=null)&&(cert.get_seclevel()!=cur_SL()))) {
   cert=new BCert.Certificate();

   if (MSPR.fixed_identity()) {
    byte random[]=Utils.parse_hex_string("bee27cbf64aac0c94cd60ff28a05e1b4");
    cert.set_random(random);

    cert.set_seclevel(cur_SL());

    cert.set_uniqueid(get_uniqueid());

    cert.set_prvkey_sign(sign_key.prv_bytes());
    cert.set_pubkey_sign(sign_key.pub_bytes());

    cert.set_pubkey_enc(enc_key.pub_bytes());
   } else {
    byte random[]=ECC.bi_bytes(ECC.random(128));
    cert.set_random(random);

    cert.set_seclevel(cur_SL());

    cert.set_uniqueid(get_uniqueid());

    cert.set_prvkey_sign(sign_key.prv_bytes());
    cert.set_pubkey_sign(sign_key.pub_bytes());

    cert.set_pubkey_enc(enc_key.pub_bytes());
   }
  }

  return cert;
 }

 public BCert.CertificateChain get_cert_chain() {
  if ((cert_chain==null)||changed()||((cert!=null)&&(cert.get_seclevel()!=cur_SL()))) {
   if (MSPR.fixed_identity()) {
    //random k for ECC signing (BCert generation)
    BigInteger r=ECC.make_bi(Utils.reverse_hex_string("062dd035241da79eedbc2abc9d99ab5b159788bb78d56aedcc3b603018ec02f7"));
    ECC.set_random(r);
   }

   BCert.CertificateChain gcert=get_group_cert();

   cert_chain=gcert.insert(get_cert());

   cert_chain.save("genchain");
  }

  return cert_chain;
 }

 public static Device cur_device() {
  boolean need_device=changed();

  if (need_device||((curdev!=null)&&(curdev.get_cert().get_seclevel()!=cur_SL()))) {
   String serial=Vars.get_str("SERIAL");
   String mac=Vars.get_str("MAC");

   curdev=new Device(serial,mac);
  }

  return curdev;
 }
}
