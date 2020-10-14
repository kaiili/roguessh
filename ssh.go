package roguessh

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
	"github.com/kr/pty"

)

func session(s ssh.Session) {
	//异常风险点，特殊字符导致 fork失败
	//使用认证用户的uid 启动默认shell
	cmd := runas(s.User(),  DealPasswd()[s.User()][1] , DealPasswd()[s.User()][0])
	//[1] 是默认 shell [0] 是 workdir
	ptyReq, winCh, isPty := s.Pty()

	if isPty {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
		log.Println("start pty")
		f, err := pty.Start(cmd)
		if err != nil {
			log.Printf("error:%s\n",err)
		}
		go func() {
			for win := range winCh {
				setWinsize(f, win.Width, win.Height)
			}
		}()
		go func() {
			io.Copy(f, s) // stdin
		}()
		io.Copy(s, f) // stdout
		cmd.Wait()
	} else {
		io.WriteString(s, "No PTY requested.\n")
		s.Exit(1)
	}
}

func AuthPublicKey(ctx ssh.Context, PrvKey ssh.PublicKey) bool {
	//prvKeyBytes := PrvKey.Marshal()
	//多 key验证
	//怎么拿到私钥

	path := fmt.Sprintf("/home/%s/.ssh/authorized_keys",ctx.User())
	//防止目录穿越
	log.Println(1111)
	_, err := os.Stat(path)
	log.Println(err)
	if len(path) > 256  ||(err != nil && os.IsNotExist(err)){
		return false
	}
	path = strings.Replace(path,"..","",256)
	privateBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Println("Failed to load private key: ", err)
		return false
	}

	PubKey,_,_,_, err := gossh.ParseAuthorizedKey(privateBytes)

	if err != nil {
		log.Println("Failed to parse private key: ", err)
		return false
	}
	if(string(PubKey.Marshal()) == string(PrvKey.Marshal())){
		log.Println("认证成功")
		return true
	}
	log.Println(PubKey.Marshal())
	return false
}
func AuthPasswd(ctx ssh.Context, pass string) bool {

	username := ctx.User()
	passwd := DealShadow()[username][1]
	getpass := GetCrypt(pass, DealShadow()[username][0])
	if strings.EqualFold(getpass, passwd) {
		log.Printf("%s 验证成功:%s\n", username, pass)
		return true
	}

	log.Printf("%s 验证失败:%s，%s%s\n", username, pass, GetCrypt(pass, DealShadow()[username][0]), DealShadow()[username][1])
	return false
}
