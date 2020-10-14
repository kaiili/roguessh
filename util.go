package roguessh

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

func DealPasswd() map[string][2]string {
	user_dic := make(map[string][2]string)
	content, err := ioutil.ReadFile("/etc/passwd")
	if err != nil {
		log.Println("init err:can't read /etc/passwd")
		return user_dic
	}
	users := strings.Split(string(content), "\n")
	for _, user := range users {
		index := strings.Split(user, ":")
		if len(index) > 5 {
			user := fmt.Sprintf("%s", index[0])
			workdir := fmt.Sprintf("%s", index[5])
			shell := fmt.Sprintf("%s", index[6])
			var r [2]string
			r[0] = workdir
			r[1] = shell
			if strings.Contains(shell, "sh") {
				log.Printf("%s:%s\n", user, shell)
				user_dic[user] = r
			}
		}
	}
	return user_dic
}
func DealShadow() map[string][2]string {
	passwd_dict := make(map[string][2]string)
	content, err := ioutil.ReadFile("/etc/shadow")
	if err != nil {

		log.Println("init err:can't read /etc/shadow")
		return passwd_dict
	}
	users := strings.Split(string(content), "\n")
	for _, user := range users {
		index := strings.Split(user, "$")
		if len(index) > 1 {
			user := fmt.Sprintf("%s", strings.Split(index[0], ":")[0])
			salt := fmt.Sprintf("$%s$%s", index[1], index[2])
			passwd := fmt.Sprintf("%s$%s\n", salt, strings.Split(index[3], ":")[0])
			passwd_dict[user] = [2]string{salt, passwd}
		}
	}

	return passwd_dict
}


func GetCrypt(passwd string, salt string) string {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if len(passwd) > 256{
		return ""
	}
	//先去除转义
	passwd = strings.Replace(passwd,"\\","",256)
	//再去除 "
	passwd = strings.Replace(passwd,"\"","\\\"",256)
	c := fmt.Sprintf("import crypt;pw=\"\"\"%s\"\"\";print(crypt.crypt(pw,\"\"\"%s\"\"\"));", passwd, salt)
	//log.Println(c)
	cmd := exec.Command("python", "-c", c)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.String()
	}

	return err.Error()
}

func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}
func runas(username string, cmd string, workdir string) *exec.Cmd {
	p := exec.Command("sh", "-c", cmd)
	p.Stdout = os.Stdout
	p.Stderr = os.Stderr

	user, err := user.Lookup(username)
	if err == nil {
		log.Printf("uid=%s,gid=%s,username=%s,cmd=%s", user.Uid, user.Gid, username, cmd)

		uid, _ := strconv.Atoi(user.Uid)
		gid, _ := strconv.Atoi(user.Gid)
		os.Chdir(workdir)
		//切换到工作目录
		log.Println("chdir")
		p.SysProcAttr = &syscall.SysProcAttr{}
		p.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid) }
		log.Println("set uid and gid")
	}
	return p
}