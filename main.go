package main

import (
  "log"
  "crypto/tls"
  "github.com/docker/parsec/client"
)

func main(){
  c, err := client.InitClient()
  if err != nil {
    log.Println(err)
    return
  }

  k, err := c.KeyGet("keyid1")
  if err != nil {
    log.Println(err)
    return
  }
  cert, err := client.X509KeyPair([]byte{}, k)
  if err != nil {
      log.Println(err)
      return
  }
  config := &tls.Config{Certificates: []tls.Certificate{*cert}}
  log.Println(config)
}
