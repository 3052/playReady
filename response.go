package main

import (
   "flag"
   "fmt"
   "os"
   "os/exec"
)

func main() {
   err := os.Setenv("PATH", "C:/Program Files/Android/Android Studio/jbr/bin")
   if err != nil {
      panic(err)
   }
   compile := flag.Bool("c", false, "compile")
   flag.Parse()
   if *compile {
      cmd := exec.Command(
         "javac", "-d", ".", "*.java", "helpers/*.java", "mod/mspr/*.java",
      )
      cmd.Stderr = os.Stderr
      cmd.Stdout = os.Stdout
      fmt.Println(cmd.Args)
      err := cmd.Run()
      if err != nil {
         panic(err)
      }
   }
   //os.Remove("secrets/genchain")
   data, err := exec.Command("java", "agsecres.tool.Response").CombinedOutput()
   os.Stdout.Write(data)
   if err != nil {
      panic(err)
   }
}
