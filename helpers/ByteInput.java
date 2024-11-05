/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS    */
/* OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,*/
/* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL    */
/* SECURITY EXPLORATIONS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, */
/* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF  */
/* OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE     */
/* SOFTWARE.                                                                  */

package agsecres.helper;

import java.lang.*;
import java.io.*;

public class ByteInput {
   String source;
   byte data[];
   int off;
   boolean le;

   public byte peek_1() {
      return data[off];
   }

   public byte read_1() {
      byte res = peek_1();

      off++;

      return res;
   }

   public short peek_2() {
      short v1 = (short)(((short) data[off]) & 0xff);
      short v2 = (short)(((short) data[off + 1]) & 0xff);

      if (le) return (short)((v2 << 8) | v1);
      else return (short)((v1 << 8) | v2);
   }

   public short read_2() {
      short res = peek_2();

      off += 2;

      return res;
   }

   public int peek_4() {
      int v1 = (int)(((int) data[off]) & 0xff);
      int v2 = (int)(((int) data[off + 1]) & 0xff);
      int v3 = (int)(((int) data[off + 2]) & 0xff);
      int v4 = (int)(((int) data[off + 3]) & 0xff);

      if (le) return (v4 << 24) | (v3 << 16) | (v2 << 8) | v1;
      else return (v1 << 24) | (v2 << 16) | (v3 << 8) | v4;
   }

   //this one is weird...
   public int peek_3() {
      int v1 = (int)(((int) data[off]) & 0xff);
      int v2 = (int)(((int) data[off + 1]) & 0xff);
      int v3 = (int)(((int) data[off + 2]) & 0xff);

      if (le) return (v3 << 16) | (v2 << 8) | v1;
      else return (v1 << 16) | (v2 << 8) | v3;
   }

   public long peek_8() {
      long v1 = (long)(((long) data[off]) & 0xff);
      long v2 = (long)(((long) data[off + 1]) & 0xff);
      long v3 = (long)(((long) data[off + 2]) & 0xff);
      long v4 = (long)(((long) data[off + 3]) & 0xff);
      long v5 = (long)(((long) data[off + 4]) & 0xff);
      long v6 = (long)(((long) data[off + 5]) & 0xff);
      long v7 = (long)(((long) data[off + 6]) & 0xff);
      long v8 = (long)(((long) data[off + 7]) & 0xff);

      if (le) return (v8 << 56) | (v7 << 48) | (v6 << 40) | (v5 << 32) | (v4 << 24) | (v3 << 16) | (v2 << 8) | v1;
      else return (v1 << 56) | (v2 << 48) | (v3 << 40) | (v4 << 32) | (v5 << 24) | (v6 << 16) | (v7 << 8) | v8;
   }

   public byte[] peek_n(int n) {
      byte res[] = new byte[n];
      System.arraycopy(data, off, res, 0, n);

      return res;
   }

   public int read_3() {
      int res = peek_3();

      off += 3;

      return res;
   }

   public int read_4() {
      int res = peek_4();

      off += 4;

      return res;
   }

   public long read_8() {
      long res = peek_8();

      off += 8;

      return res;
   }

   public byte[] read_n(int n) {
      byte res[] = peek_n(n);

      off += n;

      return res;
   }

   public String read_string(int maxlen) {
      byte data[] = read_n(maxlen);

      int len = maxlen;

      for (int i = 0; i < maxlen; i++) {
         if (data[i] == 0) {
            len = i;
            break;
         }
      }

      byte sdata[] = new byte[len];

      System.arraycopy(data, 0, sdata, 0, len);

      return new String(sdata);
   }

   public int set_pos(int new_off) {
      int old_off = off;
      off = new_off;

      return old_off;
   }

   public int get_pos() {
      return off;
   }

   public void skip(int cnt) {
      off += cnt;
   }

   public void little_endian() {
      le = true;
   }

   public void big_endian() {
      le = false;
   }

   public ByteInput(String source, byte data[]) {
      this.source = source;
      this.data = data;
      off = 0;
   }

   public ByteInput(byte data[]) {
      this(null, data);
   }

   public String source() {
      return source;
   }

   public int size() {
      if (data != null) return data.length;
      else return 0;
   }

   public int remaining() {
      if (data != null) {
         int cnt = data.length - off;

         if (cnt > 0) return cnt;
      }

      return 0;
   }

   public byte[] remaining_data() {
      int len = remaining();

      byte rdata[] = new byte[len];

      System.arraycopy(data, off, rdata, 0, len);

      return rdata;
   }

}
