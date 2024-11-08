/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS    */
/* OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,*/
/* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL    */
/* SECURITY EXPLORATIONS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, */
/* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF  */
/* OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE     */
/* SOFTWARE.                                                                  */

package agsecres.tool;

import agsecres.tool.*;
import java.lang.*;
import java.util.*;

public class PaddedPrinter {
   public static class PrintLevel {
      int pad;
      String header;
      String prefix;

      public PrintLevel(int pad, String header, String prefix) {
         this.pad = pad;
         this.header = header;
         this.prefix = prefix;
      }

      public int pad() {
         return pad;
      }

      public String header() {
         return header;
      }

      public String prefix() {
         return prefix;
      }
   }

   static Stack<PrintLevel> levels = new Stack<PrintLevel>();

   int lvl;
   int pad;

   public PaddedPrinter() {
      lvl = 0;
      pad = 0;
   }

   public void pad(int cnt, String header, String prefix) {
      pad += cnt;
      levels.push(new PrintLevel(pad, header, prefix));
      lvl++;

      if (header != null) {
         String line = Utils.pad(pad) + header;
         Utils.outputln(line);
      }
   }

   public void pad(int cnt) {
      pad(cnt, "");
   }

   public void pad(int cnt, String prefix) {
      pad(cnt, null, prefix);
   }

   public PrintLevel leave() {
      levels.pop();
      PrintLevel pl = peek();

      pad = pl.pad();
      lvl--;

      return pl;
   }

   public PrintLevel peek() {
      PrintLevel pl = levels.peek();

      return pl;
   }

   public static PaddedPrinter getInstance() {
      PaddedPrinter pp = new PaddedPrinter();
      pp.pad(0, "", "");

      return pp;
   }

   public void println(String s) {
      PrintLevel pl = peek();

      String line = Utils.pad(pl.pad()) + pl.prefix() + s;
      Utils.outputln(line);
   }

   public void printhex(String s, byte data[]) {
      PrintLevel pl = peek();
      Utils.print_buf(pl.pad(), s, data);
   }
}
