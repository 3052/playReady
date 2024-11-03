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
import java.util.*;
import java.math.*;

//Basic implementation of Elliptic Curve crypto ops for NIST P256r1 curve

public class ECC {
   //NIST P256r1 curve data
   //prime
   static String P = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
   static BigInteger p_bi;

   //param a
   static String A = "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc";
   static BigInteger a_bi;

   //param b
   static String B = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
   static BigInteger b_bi;

   //generator.X
   static String GX = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
   static BigInteger gx_bi;

   //generator.Y
   static String GY = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
   static BigInteger gy_bi;

   //modular param a
   static String A_MOD = "fffffffc00000004000000000000000000000003fffffffffffffffffffffffc";
   static BigInteger amod_bi;

   //modular param b
   static String B_MOD = "dc30061d04874834e5a220abf7212ed6acf005cd78843090d89cdf6229c4bddf";
   static BigInteger bmod_bi;

   //modular generator.X
   static String GX_MOD = "18905f76a53755c679fb732b7762251075ba95fc5fedb60179e730d418a9143c";
   static BigInteger gxmod_bi;

   //modular generator.Y
   static String GY_MOD = "8571ff1825885d85d2e88688dd21f3258b4ab8e4ba19e45cddf25357ce95560a";
   static BigInteger gymod_bi;

   //order
   static String ORDER = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
   static BigInteger order_bi;

   //max number of bits expected for BigInteger args
   static int MAXBIT = 256;

   static String ALL_ONES = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

   public static final int MAX_KEYGEN_TRY = 1000;

   //modular bits cnt
   static int MOD_BITS = 0x100;

   //modular factor and its inverse
   static BigInteger modfactor256_bi;
   static BigInteger inv_modfactor256_bi;

   //helper data
   //0
   static BigInteger zero_bi;
   //-1
   static BigInteger m1_bi;
   //2
   static BigInteger two_bi;
   //3
   static BigInteger three_bi;

   //sqrt power factor
   static BigInteger sqrt_pow;

   //special infinity Point
   static ECPoint INFINITY;

   //random instance
   static Random rand;

   //fixed random (for testing)
   static BigInteger fixed_random;

   //whether EC points are mapped to affine space
   public static boolean modular;

   public static void print(String s, BigInteger bi) {
      System.out.println(s + ": " + bi.toString(16));
   }

   public static void modular(boolean flag) {
      modular = flag;
   }

   public static BigInteger make_bi(String s) {
      return new BigInteger(s, 16);
   }

   public static BigInteger make_bi(byte data[], int off, int len) {
      if ((off + len) > data.length) return null;

      byte bi_data[] = new byte[len];

      System.arraycopy(data, off, bi_data, 0, len);

      String s = Utils.construct_hex_string(bi_data);
      return make_bi(s);
   }

   public static byte[] bi_bytes(BigInteger bi) {
      String s = bi.toString(16);

      return Utils.parse_hex_string(s);
   }

   static {
      p_bi = new BigInteger(P, 16);
      a_bi = new BigInteger(A, 16);
      b_bi = new BigInteger(B, 16);

      gx_bi = new BigInteger(GX, 16);
      gy_bi = new BigInteger(GY, 16);

      order_bi = new BigInteger(ORDER, 16);

      zero_bi = new BigInteger("0");
      m1_bi = new BigInteger("-1");
      two_bi = new BigInteger("2");
      three_bi = new BigInteger("3");

      modfactor256_bi = two_bi.pow(MOD_BITS).mod(p_bi);
      inv_modfactor256_bi = modfactor256_bi.modPow(m1_bi, p_bi);

      amod_bi = new BigInteger(A_MOD, 16);
      bmod_bi = new BigInteger(B_MOD, 16);

      gxmod_bi = new BigInteger(GX_MOD, 16);
      gymod_bi = new BigInteger(GY_MOD, 16);

      INFINITY = new ECPoint(make_bi(ALL_ONES), make_bi(ALL_ONES));

      rand = new Random();

      BigInteger two_pow_254 = two_bi.pow(254).mod(p_bi);
      BigInteger two_pow_222 = two_bi.pow(222).mod(p_bi);
      BigInteger two_pow_190 = two_bi.pow(190).mod(p_bi);
      BigInteger two_pow_94 = two_bi.pow(94).mod(p_bi);

      sqrt_pow = two_pow_254.subtract(two_pow_222).add(two_pow_190).add(two_pow_94).mod(p_bi);

      verify_modular_params();
   }

   public static void verify_modular_params() {
      BigInteger ares = a_bi.multiply(modfactor256_bi).mod(p_bi);
      BigInteger bres = b_bi.multiply(modfactor256_bi).mod(p_bi);

      boolean res = ares.equals(amod_bi) && bres.equals(bmod_bi);

      if (!res) {
         ERR.log("invalid modular curve params");
      }
   }

   public static BigInteger to_point(BigInteger input) {
      BigInteger res = input.multiply(modfactor256_bi).mod(p_bi);

      return res;
   }

   public static BigInteger from_point(BigInteger input) {
      BigInteger res = input.multiply(inv_modfactor256_bi).mod(p_bi);

      return res;
   }

   private static BigInteger power2(BigInteger input) {
      BigInteger res = input.multiply(input);

      return res;
   }

   public static class ECPoint {
      BigInteger x;
      BigInteger y;

      public ECPoint(BigInteger x, BigInteger y) {
         this.x = x;
         this.y = y;
      }

      public ECPoint(byte data[]) {
         if (data.length != 0x40) ERR.log("Invalid data length for ECPoint: " + data.length);

         this.x = make_bi(data, 0, 0x20);
         this.y = make_bi(data, 0x20, 0x20);
      }

      public BigInteger x() {
         return x;
      }

      public BigInteger y() {
         return y;
      }

      public boolean equals(ECPoint p) {
         return (x().equals(p.x())) && (y().equals(p.y()));
      }

      public void print(String s) {
         System.out.println(s);
         ECC.print("X", x);
         ECC.print("Y", y);
      }

      public BigInteger lambda_same(ECPoint p) {
         BigInteger x = p.x();
         BigInteger y = p.y();

         BigInteger x_squared = x.multiply(x).mod(p_bi);
         BigInteger three_times_x_squared = three_bi.multiply(x_squared).mod(p_bi);
         BigInteger three_times_x_squared_plus_a = three_times_x_squared.add(A()).mod(p_bi);

         BigInteger two_times_y = two_bi.multiply(y).mod(p_bi);
         BigInteger inv_two_times_y = two_times_y.modPow(m1_bi, p_bi);

         return three_times_x_squared_plus_a.multiply(inv_two_times_y).mod(p_bi);
      }

      public BigInteger lambda_different(ECPoint p, ECPoint q) {
         BigInteger xp = p.x();
         BigInteger yp = p.y();

         BigInteger xq = q.x();
         BigInteger yq = q.y();

         BigInteger delta_y = yq.subtract(yp).mod(p_bi);
         BigInteger delta_x = xq.subtract(xp).mod(p_bi);

         BigInteger inv_delta_x = delta_x.modPow(m1_bi, p_bi);

         return delta_y.multiply(inv_delta_x).mod(p_bi);
      }

      public ECPoint add_internal(BigInteger lambda, ECPoint p, ECPoint q) {
         BigInteger xp = p.x();
         BigInteger yp = p.y();

         BigInteger xq = q.x();
         BigInteger yq = q.y();

         BigInteger lambda_squared = lambda.multiply(lambda).mod(p_bi);

         BigInteger xr = lambda_squared.subtract(xp).subtract(xq).mod(p_bi);

         BigInteger xp_sub_xr = xp.subtract(xr).mod(p_bi);
         BigInteger lambda_mul_xp_sub_xq = lambda.multiply(xp_sub_xr).mod(p_bi);

         BigInteger yr = lambda_mul_xp_sub_xq.subtract(yp).mod(p_bi);

         return new ECPoint(xr, yr);
      }

      public ECPoint add_same(ECPoint p) {
         BigInteger lambda = lambda_same(p);

         return add_internal(lambda, p, p);
      }

      public ECPoint add_different(ECPoint p, ECPoint q) {
         BigInteger lambda = lambda_different(p, q);

         return add_internal(lambda, p, q);
      }

      //EC point add operation (P+Q=R)
      public ECPoint op_add(ECPoint q) {
         //check for identity element
         if (q == INFINITY) return this;
         else
         if (this == INFINITY) return q;

         if (this.equals(q)) {
            return add_same(this);
         } else {
            return add_different(this, q);
         }
      }

      //EC point double operation (P+P=2P)
      public ECPoint op_double() {
         return op_add(this);
      }

      //EC point scalar multiplication operation (k*P)
      public ECPoint op_multiply(BigInteger k) {
         ECPoint res = INFINITY;
         ECPoint temp = this;

         int maxbit = k.bitLength() + 1;

         if (maxbit > MAXBIT) maxbit = MAXBIT;

         for (int i = 0; i < maxbit; i++) {
            if (k.testBit(i)) {
               //Point add
               res = temp.op_add(res);
            }

            temp = temp.op_double();
         }

         return res;
      }

      public ECPoint op_neg() {
         BigInteger negy = zero_bi.subtract(y).mod(p_bi);
         return new ECPoint(x, negy);
      }

      public byte[] bytes() {
         byte data[] = new byte[0x40];

         byte x_data[] = bi_bytes(x());
         byte y_data[] = bi_bytes(y());

         System.arraycopy(x_data, 0, data, 0, 0x20);
         System.arraycopy(y_data, 0, data, 0x20, 0x20);

         return data;
      }
   }

   public static class ECKey {
      BigInteger prv;
      ECPoint pub;

      public ECKey() {
         for (int i = 0; i < MAX_KEYGEN_TRY; i++) {
            BigInteger candidate_key = random().mod(order_bi);

            ECPoint candidate = GEN().op_multiply(candidate_key);

            if (on_curve(candidate)) {
               prv = candidate_key;
               pub = candidate;
               break;
            }
         }
      }

      public ECPoint pub() {
         return pub;
      }

      public BigInteger prv() {
         return prv;
      }

      public ECKey(byte prvdata[]) {
         prv = make_bi(prvdata, 0, 0x20);
         pub = GEN().op_multiply(prv);
      }

      public static ECKey from_file(String name) {
         ECKey res = null;

         byte data[] = Utils.load_file(name);

         if (data != null) {
            res = new ECKey(data);
         }

         return res;
      }

      public byte[] prv_bytes() {
         return bi_bytes(prv);
      }

      public byte[] pub_bytes() {
         return pub.bytes();
      }

      public void print(String s) {
         System.out.println(s);
         ECC.print("- prv", prv);
         pub.print("- pub:");
      }
   }

   public static class ECSignature {
      BigInteger r;
      BigInteger s;

      public ECSignature(BigInteger r, BigInteger s) {
         this.r = r;
         this.s = s;
      }

      public BigInteger r() {
         return r;
      }

      public BigInteger s() {
         return s;
      }

      public ECSignature(byte data[]) {
         if (data.length != 0x40) ERR.log("Invalid data length for ECSignature: " + data.length);

         this.r = make_bi(data, 0, 0x20);
         this.s = make_bi(data, 0x20, 0x20);
      }

      public static ECSignature get(byte digest[], BigInteger prv) {
         BigInteger e_bi = make_bi(digest, 0, 0x20);

         BigInteger r_bi = zero_bi;
         BigInteger s_bi = zero_bi;

         BigInteger k_bi = null;

         while (r_bi.equals(zero_bi) || s_bi.equals(zero_bi)) {
            k_bi = random().mod(order_bi);

            ECPoint rpoint = GEN().op_multiply(k_bi);

            r_bi = rpoint.x().mod(order_bi);

            BigInteger t1 = k_bi.modPow(m1_bi, order_bi);
            BigInteger t2 = e_bi.add(prv.multiply(r_bi).mod(order_bi));

            s_bi = t1.multiply(t2).mod(order_bi);
         }

         return new ECSignature(r_bi, s_bi);
      }

      public boolean verify(byte digest[], ECPoint pub) {
         BigInteger e_bi = make_bi(digest, 0, 0x20);

         BigInteger w_bi = s.modPow(m1_bi, order_bi);

         BigInteger u1 = e_bi.multiply(w_bi).mod(order_bi);
         BigInteger u2 = r.multiply(w_bi).mod(order_bi);

         ECPoint t1 = GEN().op_multiply(u1);
         ECPoint t2 = pub.op_multiply(u2);

         ECPoint p = t1.op_add(t2);

         BigInteger px = p.x();

         return px.equals(r);
      }

      public void print(String str) {
         System.out.println(str);
         ECC.print("- r", r);
         ECC.print("- s", s);
      }

      public byte[] bytes() {
         byte signature[] = new byte[0x40];

         byte r_data[] = bi_bytes(r());
         byte s_data[] = bi_bytes(s());

         System.arraycopy(r_data, 0, signature, 0, 0x20);
         System.arraycopy(s_data, 0, signature, 0x20, 0x20);

         return signature;
      }
   }

   public static BigInteger random(int maxbits) {
      if (fixed_random != null) return fixed_random;

      return new BigInteger(maxbits, rand);
   }

   public static BigInteger random() {
      return random(MAXBIT);
   }

   public static ECPoint GEN() {
      if (modular) {
         return new ECPoint(gxmod_bi, gymod_bi);
      } else {
         return new ECPoint(gx_bi, gy_bi);
      }
   }

   public static BigInteger A() {
      if (modular) {
         return amod_bi;
      } else {
         return a_bi;
      }
   }

   public static BigInteger B() {
      if (modular) {
         return bmod_bi;
      } else {
         return b_bi;
      }
   }

   private static BigInteger curve_value(BigInteger x) {
      BigInteger x_pow_2 = power2(x).mod(p_bi);
      BigInteger x_pow_2_plus_a = x_pow_2.add(A()).mod(p_bi);
      BigInteger x_pow_3_plus_ax = x_pow_2_plus_a.multiply(x).mod(p_bi);
      BigInteger x_pow_3_plus_ax_plus_b = x_pow_3_plus_ax.add(B()).mod(p_bi);

      return x_pow_3_plus_ax_plus_b;
   }

   public static boolean on_curve(ECPoint p) {
      BigInteger x = p.x();
      BigInteger y = p.y();

      BigInteger x_pow_3_plus_ax_plus_b = curve_value(x);
      BigInteger y_pow_2 = power2(y).mod(p_bi);

      return x_pow_3_plus_ax_plus_b.equals(y_pow_2);
   }

   //r = c^(2^254-2^222+2^190+2^94) = sqrt(c) mod p256
   //source: "Mathematical routines for the NIST prime elliptic curves"
   //        Routine 3.2.10 mp_mod_sqrt_256, page 24
   public static BigInteger sqrt(BigInteger x) {
      return x.modPow(sqrt_pow, p_bi);
   }

   public static BigInteger y_from_x(BigInteger x) {
      BigInteger x_pow_2 = power2(x);
      BigInteger x_pow_2_plus_a = x_pow_2.add(A());
      BigInteger x_pow_3_plus_ax = x_pow_2_plus_a.multiply(x);
      BigInteger x_pow_3_plus_ax_plus_b = x_pow_3_plus_ax.add(B());

      BigInteger y = sqrt(x_pow_3_plus_ax_plus_b);

      return y;
   }

   public static ECPoint[] encrypt(ECPoint plaintext, ECPoint pub) {
      BigInteger k = random().mod(order_bi);

      ECPoint point1 = GEN().op_multiply(k);
      ECPoint point2 = pub.op_multiply(k).op_add(plaintext);

      return new ECPoint[] {
         point1,
         point2
      };
   }

   public static ECPoint[] encrypt(BigInteger plaintext, ECPoint pub) {
      BigInteger y = y_from_x(plaintext);

      ECC.ECPoint p = new ECPoint(plaintext, y);

      if (!ECC.on_curve(p)) return null;

      ECPoint encrypted[] = encrypt(p, pub);

      return encrypted;
   }

   public static ECPoint decrypt(ECPoint encrypted[], BigInteger prv) {
      ECPoint point1 = encrypted[0];
      ECPoint point2 = encrypted[1];

      ECPoint tmp = point1.op_multiply(prv);
      ECPoint negpoint = tmp.op_neg();
      ECPoint plaintext = point2.op_add(negpoint);

      return plaintext;
   }

   public static void set_random(BigInteger r) {
      fixed_random = r;
   }

   public static void clear_random() {
      fixed_random = null;
   }
}
