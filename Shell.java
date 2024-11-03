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
import java.io.*;
import java.nio.charset.*;

public class Shell {
 //Windows console CP to support Polish characters
 public static final String CODE_PAGE = "Cp852";

 public static final Charset CHARSET = Charset.forName(CODE_PAGE);

 public static final PrintWriter CONSOLE_OUTPUT = new PrintWriter(System.out,true,CHARSET);

 public static PrintWriter out=CONSOLE_OUTPUT;

 public static PaddedPrinter pp;

 public static final String args_info[] = {
  "v",
  "[-v]"
 };

 public static class Option {
  public static final int OPT_PURE_ARG = 0x00;
  public static final int OPT_NO_ARG   = 0x01;
  public static final int OPT_INT_ARG  = 0x02;
  public static final int OPT_STR_ARG  = 0x03;

  int type;
  char option;
  Object arg;

  public Option(int type,Object arg) {
   this(type,(char)0,arg);
  }

  public Option(int type,char option,Object arg) {
   this.type=type;
   this.option=option;
   this.arg=arg;
  }

  public Option(int type,char option) {
   this.type=type;
   this.option=option;
   this.arg=null;
  }

  public int int_arg() {
   return ((Integer)arg).intValue();
  }

  public String str_arg() {
   return (String)arg;
  }

  public boolean pure_arg() {
   if (type==OPT_PURE_ARG) return true;
    else return false;
  }

  public boolean no_arg() {
   if (type==OPT_NO_ARG) return true;
    else return false;
  }
 }

 public static class ScriptArgs {
  public static final String EMPTY_ARG = "";

  String args[];
  boolean assert_status;

  public ScriptArgs(Option options[]) {
   int len=options.length;

   args=new String[len];

   for(int i=0;i<len;i++) {
    args[i]=options[i].str_arg();
   }

   assert_status=true;
  }

  public ScriptArgs(String args[]) {
   this.args=args;

   assert_status=true;
  }

  public ScriptArgs() {
   this(new String[0]);
  }

  public int argnum() {
   return args.length-1;
  }

  public String get_arg(int idx) {
   if (idx<args.length) {
    return args[idx];
   } else return EMPTY_ARG;
  }

  public boolean assert_status() {
   return assert_status;
  }

  public void assert_status(boolean val) {
   assert_status=val;
  }
 };

 public static class ScriptContext {
  int curlvl;
  int maxlvl;
  ScriptArgs level[];

  public ScriptContext(int maxlvl) {
   this.curlvl=0;
   this.maxlvl=maxlvl;

   level=new ScriptArgs[maxlvl];
  }

  public void push(ScriptArgs args) {
   if (curlvl<maxlvl) {
    level[curlvl++]=args;
   } else {
    Shell.report_error("too many script execution levels");
    System.exit(1);
   }
  }

  public ScriptArgs pop() {
   if (curlvl>0) {
    return level[--curlvl];
   } else {
    Shell.report_error("unexpected script execution level");
    System.exit(1);
   }

   return null;
  }

  public String get_arg(int idx) {
   if (curlvl>0) {
    if (level[curlvl-1]!=null) {
     return level[curlvl-1].get_arg(idx);
    }
   }

   return ScriptArgs.EMPTY_ARG;
  }

  public int argnum() {
   if (curlvl>0) {
    if (level[curlvl-1]!=null) {
     return level[curlvl-1].argnum();
    }
   }

   return 0;
  }

  public boolean assert_status() {
   if (curlvl>0) {
    if (level[curlvl-1]!=null) {
     return level[curlvl-1].assert_status();
    }
   }

   return false;
  }

  public void assert_status(boolean val) {
   if (curlvl>0) {
    if (level[curlvl-1]!=null) {
     level[curlvl-1].assert_status(val);
    }
   }
  }
 };

 public static final String BANNER = "# MS Play Ready / Canal+ VOD toolkit\n" +
                                     "# (c) Security Explorations    2016-2019 Poland\n" +
                                     "# (c) AG Security Research     2019-2022 Poland\n";

 public static final String PROMPT       = "msprcp> ";

 public static final String COMMENT_CHAR = "#";

 public static final String DEFAULT_SCRIPTS_DIR = "scripts";
 public static final String INIT_SCRIPT         = "init.scr";

 public static final char OPT_INTEGER = 'I';
 public static final char OPT_STRING  = 'S';
 public static final char OPT_COLON   = ':';

 public static boolean verbose;

 private static final int OP_MANDATORY = 0x01;
 private static final int OP_OPTIONAL  = 0x02;

 private static BufferedReader input;
 private static boolean running;

 static boolean echo=true;
 static boolean comm=true;
 
 public static String err_string;

 private static ScriptContext scrcontext;
 public static int LINESIZE = 16;

 static {
  try {
   input=new BufferedReader(new InputStreamReader(System.in,"utf-8"));
   scrcontext=new ScriptContext(0x20);
  } catch(Throwable t) {}
 }

 public static PrintWriter getOutput() {
  return out;
 }

 public static void setOutput(PrintWriter pw) {
  out=pw;
 }

 public static void closeOutput() {
  out.close();
 }

 public static void stop() throws Throwable {
  running=false;
 }

 public static boolean echo() {
  return echo;
 }

 public static void echo(boolean val) {
  echo=val;
 }

 public static boolean comm() {
  return comm;
 }

 public static void comm(boolean val) {
  comm=val;
 }

 private static boolean is_option_type(char opt) {
  if ((opt==OPT_INTEGER)||(opt==OPT_STRING)) return true;
   else return false;
 }

 public static Option getopt(Option options[],char opt) {
  for(int i=0;i<options.length;i++) {
   Option o=options[i];
   if (o.option==opt) return o;
  }

  return null;
 }

 public static void report_error(String err) {
  System.err.println("error: "+err);
 }

 private static String read_line() throws Throwable {
  err_string=null;

  System.out.print(PROMPT);

  return input.readLine().trim();
 }

 private static String read_line(BufferedReader script) throws Throwable {
  err_string=null;
  
  if (echo) System.out.print(PROMPT);

  String line=null;
  try {
   line=script.readLine().trim();
  } catch(Throwable t) {}

  return line;
 }

 private static boolean is_comment(String line) {
  if (line.startsWith(COMMENT_CHAR)) return true;
   else return false;
 }

 public static void print(String line) {
  getOutput().print(line);
  getOutput().flush();
 }

 public static void println(String line) {
  getOutput().println(line);
 }

 public static void outputln(String line) {
  getOutput().println(line);
  out.flush();
 }

 public static void output_buf(String s,byte data[]) throws Throwable {
  if (s!=null) {
   getOutput().print(s+": ");
  }

  for(int i=0;i<data.length;i++) {
   getOutput().print(Utils.hex_value((data[i]&0xff),2)+" ");
  }
     
  getOutput().println("");
 }

 public static String hex_value(int val,int max) {
  String s="";
  for(int i=0;i<max;i++) {
   s+="0";
  }

  s+=Integer.toHexString(val);

  return s.substring(s.length()-max);
 }

 private static void print_line(int addr,byte tab[],int pos) {
  String str=hex_value(addr+pos,4)+": ";

  int size=tab.length-pos;
   
  if (size>LINESIZE) size=LINESIZE;

  for(int i=pos;i<(pos+size);i++) {
   str+=" "+hex_value((int)tab[i],2);
  }

  if (size<LINESIZE) {
   for(int i=0;i<(LINESIZE-size);i++) {
    str+="   ";
   }
  }

  str+="  ";  

  for(int i=pos;i<(pos+size);i++) {
   str+=Utils.char_value((char)tab[i]);
  }

  outputln(str);
 }

 public static void print_mem(int addr,byte tab[]) {
  try {
   int pos=0;
  
   while(pos<tab.length) {
    print_line(addr,tab,pos);
    pos+=LINESIZE;
   }
  } catch(Throwable t) {}
 }

 public static void print_buf(String s,byte tab[]) {
  outputln(s);  
  print_mem(0,tab);
 }

 public static PaddedPrinter get_pp() {
  if (pp==null) {
   pp=PaddedPrinter.getInstance();
  }

  return pp;
 }

 public static int argnum() {
  return scrcontext.argnum();
 }

 public static boolean assert_status() {
  return scrcontext.assert_status();
 }

 public static void assert_status(boolean val) {
  scrcontext.assert_status(val);
 }

 public static void usage() {
  System.out.println("shell "+args_info[1]);
  System.out.println("       where:");
  System.out.println("              -v     : enable verbose debugging");
  System.exit(1);
 }

}
