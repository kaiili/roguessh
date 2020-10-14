package main

import "roguessh"
/*

1，丰富配置
2，常驻，守护进程
3，获取私钥
 */
func main() {
 roguessh.Run("127.0.0.1:2222")
}
