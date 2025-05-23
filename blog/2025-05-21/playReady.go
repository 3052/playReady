package main

import (
    "fmt"
    "io"
    "net/http"
    "strings"
    "tanith.neocities.org/goplayready/challenge"
    "tanith.neocities.org/goplayready/device"
)

var filePath = "./devices/hisense/"

func main() {
    var device device.LocalDevice

    err := device.Load(filePath)

    if err != nil {
        fmt.Println(err)
    }

    var Challenge challenge.Challenge

    data, err := Challenge.Create(device)

    if err != nil {
        fmt.Println(err)
    }
    var reader io.Reader = strings.NewReader(data)

    resp, err := http.Post(
        "https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=(persist:false,ck:AAAAAAAAAAAAAAAAAAAAAA==,kid:AAAAAAAAAAAAAAAAAAAAAA==,ckt:aesctr)",
        "text/xml; charset=UTF-8", reader)
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        fmt.Println("Error reading response body:", err)
        return
    }

    fmt.Println(string(body))
}
