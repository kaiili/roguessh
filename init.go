package roguessh

import (
	"github.com/gliderlabs/ssh"
	"log"
)

func Run(addr string) {
	ssh.Handle(session)
	publicKeyOption := ssh.PublicKeyAuth(AuthPublicKey)
	passwdOption := ssh.PasswordAuth(AuthPasswd)
	log.Println("starting ssh server on port 2222...")
	log.Fatal(ssh.ListenAndServe(addr, nil, publicKeyOption, passwdOption))
}
