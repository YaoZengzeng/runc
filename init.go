package main

import (
	"os"
	"runtime"

	"github.com/opencontainers/runc/libcontainer"
	// 引用了nsenter这个包
	_ "github.com/opencontainers/runc/libcontainer/nsenter"
	"github.com/urfave/cli"
)

func init() {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		runtime.GOMAXPROCS(1)
		runtime.LockOSThread()
	}
}

var initCommand = cli.Command{
	Name:  "init",
	// "runc init"初始化namespace并且启动进程（不要在runc以外调用它）
	Usage: `initialize the namespaces and launch the process (do not call it outside of runc)`,
	Action: func(context *cli.Context) error {
		factory, _ := libcontainer.New("")
		if err := factory.StartInitialization(); err != nil {
			// as the error is sent back to the parent there is no need to log
			// or write it to stderr because the parent process will handle this
			// 错误会返回给parent，因此不用进行log或者写到stderr，因为父进程会对它进行处理
			os.Exit(1)
		}
		panic("libcontainer: container init failed to exec")
	},
}
