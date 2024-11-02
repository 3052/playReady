/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS    */
/* OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,*/
/* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL    */
/* SECURITY EXPLORATIONS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, */
/* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF  */
/* OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE     */
/* SOFTWARE.                                                                  */

package agsecres.tool;

import java.lang.*;
import java.util.*;

public class Vars {
   public static final int VAR_INT = 0x01;
   public static final int VAR_STR = 0x02;

   public static class Proto {
      String name;
      int type;

      public Proto(String name, int type) {
         this.name = name;
         this.type = type;
      }

      public String name() {
         return name;
      }

      public int type() {
         return type;
      }
   }

   public static class Var {
      Proto proto;
      Object val;

      public Var(Proto proto, Object val) {
         this.proto = proto;
         this.val = val;
      }

      public Var(Proto proto) {
         this(proto, null);
      }

      public Proto proto() {
         return proto;
      }

      public Object val() {
         return val;
      }

      public void set(Object val) {
         this.val = val;
      }
   }

   public static final int MAXVARNAME = 20;

   public static final int UNKNOWN_VAL = -1;

   static Vector < Var > vars;

   static {
      vars = new Vector < Var > ();
   }

   public static Var get_var(String name) {
      for (int i = 0; i < vars.size(); i++) {
         Var
         var = vars.elementAt(i);
         Proto proto =
            var.proto();

         if (proto.name().equals(name)) return var;
      }

      return null;
   }

   static boolean known_var(String name) {
      if (get_var(name) != null) return true;
      else return false;
   }

   static int str2type(String s) {
      if (s.equals("int")) return VAR_INT;
      else
      if (s.equals("str")) return VAR_STR;
      else return -1;
   }

   public static void declare(String name, String stype) {
      int type = -1;

      if (known_var(name)) {} else {
         type = str2type(stype);

         if (type == -1) {} else {
            switch (type) {
            case VAR_INT:
               declare(new Proto(name, VAR_INT));
               break;
            case VAR_STR:
               declare(new Proto(name, VAR_STR));
               break;
            }
         }
      }
   }

   public static void declare(Proto p) {
      if (!known_var(p.name())) {
         vars.addElement(new Var(p));
      }
   }

   public static void set(String name, int val) {
      if (!known_var(name)) {
         declare(new Proto(name, VAR_INT));
      }
      Var v = get_var(name);
      v.set(Integer.valueOf(val));
   }

   public static void set(String name, String val) {
      if (!known_var(name)) {
         declare(new Proto(name, VAR_STR));
      }

      Var v = get_var(name);

      v.set(val);
   }

   public static void clear(String name) {
      Var v = get_var(name);

      if (v != null) {
         v.set(null);
      }
   }

   public static int get_int(Var
      var) {
      Integer ival = (Integer) var.val();

      return ival.intValue();
   }

   public static String get_str(Var
      var) {
      return (String) var.val();
   }

   public static int get_int(String name) {
      Var
      var = get_var(name);

      return get_int(var);
   }

   public static String get_str(String name) {
      Var
      var = get_var(name);

      return get_str(var);
   }

   public static void print() {
      for (int i = 0; i < vars.size(); i++) {
         Var
         var = vars.elementAt(i);
         Proto proto =
            var.proto();

         String p = proto.name();
         String val = "";

         if (var.val() != null) {
            switch (proto.type()) {
            case VAR_INT:
               val += Utils.hex_value(get_int(var), 8);
               break;
            case VAR_STR:
               val += "\"" + get_str(var) + "\"";
               break;
            }
         } else {
            val += "<not set>";
         }

      }
   }
}
