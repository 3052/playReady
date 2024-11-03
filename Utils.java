/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS    */
/* OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,*/
/* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL    */
/* SECURITY EXPLORATIONS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, */
/* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF  */
/* OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE     */
/* SOFTWARE.                                                                  */

package agsecres.tool;

import java.lang.*;
import java.io.*;
import java.util.*;
import java.text.*;

public class Utils {
   public static final int LINESIZE = 16;

   // static PrintWriter out=new PrintWriter(System.out);

   private static String allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890!@#$%^&*()_+-={}[]|:\";',.<>?/";

   public static int parse_hex_value(String s) {
      int val = 0;

      for (int i = 0; i < s.length(); i++) {
         char ch = s.charAt(i);
         int d;

         if ((ch >= '0') && (ch <= '9')) {
            d = ch - '0';
         } else

         if ((ch >= 'a') && (ch <= 'f')) {
            d = 10 + ch - 'a';
         } else

         if ((ch >= 'A') && (ch <= 'F')) {
            d = 10 + ch - 'A';
         } else return -1;

         val = (val << 4) | (d & 0x0f);
      }

      return val;
   }

   public static int int_value(String s) {
      int res = -1;

      try {
         res = Integer.parseInt(s);
      } catch (Throwable t) {}

      return res;
   }

   public static long long_value(String s) {
      long res = -1;

      try {
         res = Long.parseLong(s);
      } catch (Throwable t) {}

      return res;
   }

   public static String hex_value(int val, int max) {
      String s = "";
      for (int i = 0; i < max; i++) {
         s += "0";
      }

      s += Integer.toHexString(val);

      return s.substring(s.length() - max);
   }

   public static String hex_value(long val, int max) {
      String s = "";
      for (int i = 0; i < max; i++) {
         s += "0";
      }

      s += Long.toHexString(val);

      return s.substring(s.length() - max);
   }

   public static String char_value(char c) {
      char tab[] = new char[1];

      if (allowed_chars.indexOf(c) != -1) {
         tab[0] = c;
         return new String(tab);
      } else return ".";
   }

   public static String padded_int(int val, int max) {
      String s = "";
      for (int i = 0; i < max; i++) {
         s += "0";
      }

      s += val;

      return s.substring(s.length() - max);
   }

   public static String padded_string(String s, int space) {
      int cnt = s.length();

      String pad = "";

      if (cnt < space) {
         pad = s;

         for (int i = 0; i < (space - cnt); i++) {
            pad += " ";
         }
      } else pad = s.substring(s.length() - space);

      return pad;
   }

   public static String pad(int cnt, String ch) {
      String pad = "";

      for (int i = 0; i < cnt; i++) {
         pad += ch;
      }

      return pad;
   }

   public static String pad(int cnt) {
      return pad(cnt, " ");
   }

   public static String padded_string_left(String s, int space) {
      int cnt = s.length();

      String pad = "";

      if (cnt < space) {
         for (int i = 0; i < (space - cnt); i++) {
            pad += " ";
         }

         pad += s;
      } else pad = s.substring(s.length() - space);

      return pad;
   }

   public static byte[] parse_hex_string(String s) {
      int len = s.length();

      if ((len & 0x01) != 0) {
         s = "0" + s;
         len++;
      }

      len /= 2;

      byte aid[] = new byte[len];

      for (int i = 0; i < len; i++) {
         aid[i] = (byte) parse_hex_value(s.substring(2 * i, 2 * (i + 1)));
      }

      return aid;
   }

   public static String construct_hex_string(byte buf[]) {
      String s = "";

      for (int i = 0; i < buf.length; i++) {
         s += hex_value(((int) buf[i]) & 0xff, 2);
      }

      return s;
   }

   public static void outputln(String line) {
      System.out.println(line);
      //out.flush();
   }

   public static void output_buf(String s, byte data[]) throws Throwable {
      if (s != null) {
         System.out.print(s + ": ");
      }

      for (int i = 0; i < data.length; i++) {
         System.out.print(Utils.hex_value((data[i] & 0xff), 2) + " ");
      }

      System.out.println("");
   }

   private static void print_line(int pad, int addr, byte tab[], int pos) {
      String str = pad(pad) + hex_value(addr + pos, 4) + ": ";

      int size = tab.length - pos;

      if (size > LINESIZE) size = LINESIZE;

      for (int i = pos; i < (pos + size); i++) {
         str += " " + hex_value((int) tab[i], 2);
      }

      if (size < LINESIZE) {
         for (int i = 0; i < (LINESIZE - size); i++) {
            str += "   ";
         }
      }

      str += "  ";

      for (int i = pos; i < (pos + size); i++) {
         str += Utils.char_value((char) tab[i]);
      }

      outputln(str);
   }

   public static void print_mem(int pad, int addr, byte tab[]) {
      try {
         int pos = 0;

         while (pos < tab.length) {
            print_line(pad, addr, tab, pos);
            pos += LINESIZE;
         }
      } catch (Throwable t) {}
   }

   public static void print_buf(int pad, String s, byte tab[]) {
      outputln(pad(pad) + s);
      print_mem(pad + 2, 0, tab);
   }

   public static String[] tokenize(String s, String token) {
      s = s.trim();

      StringTokenizer st = new StringTokenizer(s, token, false);
      int cnt = st.countTokens();

      String tokens[] = new String[cnt];

      for (int i = 0; i < cnt; i++) {
         tokens[i] = st.nextToken();
      }

      return tokens;
   }

   public static byte[] reverse(byte data[]) {
      byte output[] = new byte[data.length];

      for (int i = 0; i < data.length; i++) {
         output[i] = data[data.length - i - 1];
      }

      return output;
   }

   public static String reverse_hex_string(String s) {
      byte data[] = parse_hex_string(s);

      return construct_hex_string(reverse(data));
   }

   public static byte[] load_file(String path) {
      byte data[] = null;

      try {
         File f = new File(path);

         if (f.exists() && (!f.isDirectory())) {
            int len = (int) f.length();

            data = new byte[len];

            FileInputStream fis = new FileInputStream(path);
            fis.read(data);
            fis.close();
         }

      } catch (Throwable t) {
         data = null;
      }

      return data;
   }

   public static String load_text_file(String path) {
      String result = null;

      try {
         File f = new File(path);

         if (f.exists() && (!f.isDirectory())) {
            result = "";

            BufferedReader b = new BufferedReader(new InputStreamReader(new FileInputStream(path), "utf-8"));
            String line = b.readLine();

            while (line != null) {
               result = result + line;
               line = b.readLine();
            }
         }
      } catch (Throwable t) {
         result = null;
      }

      return result;
   }

   public static boolean save_file(String path, byte data[]) {
      boolean res = false;

      try {
         File f = new File(path);

         if (f.exists()) {
            f.delete();
         }

         if (!f.exists()) {
            FileOutputStream fos = new FileOutputStream(path);
            fos.write(data);
            fos.close();

            res = true;
         }
      } catch (Throwable t) {}

      return res;
   }

   public static String long2date(long val) {
      String res = "";

      try {
         DateFormat f = new SimpleDateFormat("yyyy/MM/dd hh:mm aaa");
         f.setTimeZone(TimeZone.getTimeZone("UTC"));

         Date d = f.parse("1904/01/01 12:00 AM");

         long timeval = d.getTime() + val * 1000L;

         d = new Date(timeval);

         res = d.toString();
      } catch (Throwable t) {}

      return res;
   }

   public static long date2long(String sdate) {
      long timeval = -1L;

      try {
         DateFormat f = new SimpleDateFormat("yyyy/MM/dd hh:mm:ss aaa");
         f.setTimeZone(TimeZone.getTimeZone("UTC"));

         Date base = f.parse("1904/01/01 12:00:00 AM");
         long base_timeval = base.getTime();

         Date d = f.parse(sdate);
         timeval = (d.getTime() - base_timeval) / 1000L;
      } catch (Throwable t) {}

      return timeval;
   }

   public static long current_date() {
      long timeval = -1L;

      try {
         DateFormat f = new SimpleDateFormat("yyyy/MM/dd hh:mm:ss aaa");
         f.setTimeZone(TimeZone.getTimeZone("UTC"));

         Date base = f.parse("1904/01/01 12:00:00 AM");
         long base_timeval = base.getTime();

         Date d = new Date();
         timeval = (d.getTime() - base_timeval) / 1000L;
      } catch (Throwable t) {}

      return timeval;
   }

   public static boolean mkdir(String dir) {
      boolean res = false;

      try {
         new File(dir).mkdirs();
         res = true;
      } catch (Throwable t) {}

      return res;
   }

   public static boolean file_exists(String filename) {
      boolean res = false;

      try {
         File f = new File(filename);
         if (f.exists()) res = true;
      } catch (Throwable t) {}

      return res;
   }
}
