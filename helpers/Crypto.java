/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS    */
/* OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,*/
/* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL    */
/* SECURITY EXPLORATIONS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, */
/* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF  */
/* OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE     */
/* SOFTWARE.                                                                  */

package agsecres.helper;

import agsecres.tool.*;
import java.lang.*;
import java.security.*;
import java.util.*;
import java.math.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Crypto {
 public static String base64_encode(byte data[]) throws Throwable {
  Base64.Encoder e=Base64.getEncoder();
  return new String(e.encode(data));
 }

 public static byte[] base64_decode(String s) throws Throwable {
  Base64.Decoder d=Base64.getDecoder();
  return d.decode(s.getBytes());
 }

 public static byte[] SHA256(byte data[]) {
  byte res[]=null;

  try {
   MessageDigest md=MessageDigest.getInstance("SHA-256");
   md.update(data); 

   res=md.digest();
  } catch(Throwable t) {}

  return res;
 }

 public static byte[] MD5(byte data[]) {
  byte res[]=null;

  try {
   MessageDigest md=MessageDigest.getInstance("MD5");
   md.update(data); 

   res=md.digest();
  } catch(Throwable t) {}

  return res;
 }

 public static byte[] aes_cbc_encrypt(byte input[],byte iv[],byte key[]) throws Throwable {
  SecretKey aeskey=new SecretKeySpec(key,"AES");

  Cipher cipher=Cipher.getInstance("AES/CBC/NOPADDING");
  cipher.init(Cipher.ENCRYPT_MODE,aeskey,new IvParameterSpec(iv));

  return cipher.doFinal(input);
 }

 public static byte[] aes_cbc_decrypt(byte input[],byte iv[],byte key[]) throws Throwable {
  SecretKey aeskey=new SecretKeySpec(key,"AES");

  Cipher cipher=Cipher.getInstance("AES/CBC/NOPADDING");
  cipher.init(Cipher.DECRYPT_MODE,aeskey,new IvParameterSpec(iv));

  return cipher.doFinal(input);
 }

 public static byte[] aes_ctr_encrypt(byte input[],byte iv[],byte key[]) throws Throwable {
  SecretKey aeskey=new SecretKeySpec(key,"AES");

  Cipher cipher=Cipher.getInstance("AES/CTR/NOPADDING");
  cipher.init(Cipher.ENCRYPT_MODE,aeskey,new IvParameterSpec(iv));

  return cipher.doFinal(input);
 }

 public static byte[] aes_ctr_decrypt(byte input[],byte iv[],byte key[]) throws Throwable {
  SecretKey aeskey=new SecretKeySpec(key,"AES");

  Cipher cipher=Cipher.getInstance("AES/CTR/NOPADDING");
  cipher.init(Cipher.DECRYPT_MODE,aeskey,new IvParameterSpec(iv));

  return cipher.doFinal(input);
 }

 public static byte[] aes_ecb_encrypt(byte input[],byte key[]) throws Throwable {
  SecretKey aeskey=new SecretKeySpec(key,"AES");

  Cipher cipher=Cipher.getInstance("AES/ECB/NOPADDING");
  cipher.init(Cipher.ENCRYPT_MODE,aeskey);

  return cipher.doFinal(input);
 }

 public static byte[] aes_ecb_decrypt(byte input[],byte key[]) throws Throwable {
  SecretKey aeskey=new SecretKeySpec(key,"AES");

  Cipher cipher=Cipher.getInstance("AES/ECB/NOPADDING");
  cipher.init(Cipher.DECRYPT_MODE,aeskey);

  return cipher.doFinal(input);
 }

 public static void xor(byte input1[],byte input2[],byte output[]) throws Throwable {
  if (input1.length!=input2.length) ERR.log("Invalid arguments length to xor");

  for(int i=0;i<input1.length;i++) {
   output[i]=(byte)(input1[i]^input2[i]);
  }
 }

   public static byte[] ecdsa(byte data[],BigInteger prvkey) {
      byte digest[]=SHA256(data);
      Utils.print_buf(0,"ecdsa digest",digest);
      ECC.ECSignature ecsig=ECC.ECSignature.get(digest,prvkey);
      byte signature[]=ecsig.bytes();
      return signature;
   }

 public static byte[] ecc_encrypt(byte input[],ECC.ECPoint pubkey) {
  if (input.length!=0x20) return null;

  BigInteger plaintext=ECC.make_bi(input,0,0x20);

  ECC.ECPoint points[]=ECC.encrypt(plaintext,pubkey);

  if (points==null) return null;

  byte p1[]=points[0].bytes();
  byte p2[]=points[1].bytes();

  byte encrypted[]=new byte[p1.length+p2.length];

  System.arraycopy(p1,0,encrypted,0,p1.length);
  System.arraycopy(p2,0,encrypted,p1.length,p2.length);

  return encrypted;  
 }

 public static byte[] ecc_decrypt(byte input[],BigInteger prvkey) {
  if (input.length!=0x80) return null;

  byte p1_data[]=new byte[0x40];
  System.arraycopy(input,0,p1_data,0,0x40);

  byte p2_data[]=new byte[0x40];
  System.arraycopy(input,0x40,p2_data,0,0x40);

  ECC.ECPoint p1=new ECC.ECPoint(p1_data);
  ECC.ECPoint p2=new ECC.ECPoint(p2_data);

  ECC.ECPoint encrypted[]=new ECC.ECPoint[]{
   p1,
   p2
  };

  ECC.ECPoint decrypted=ECC.decrypt(encrypted,prvkey);

  byte plaintext[]=decrypted.bytes();

  return plaintext;
 }

}
