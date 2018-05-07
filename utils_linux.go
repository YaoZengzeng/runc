// +build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/cgroups/systemd"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/intelrdt"
	"github.com/opencontainers/runc/libcontainer/specconv"
	"github.com/opencontainers/runc/libcontainer/utils"
	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/coreos/go-systemd/activation"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"golang.org/x/sys/unix"
)

var errEmptyID = errors.New("container id cannot be empty")

// loadFactory returns the configured factory instance for execing containers.
// loadFactory返回一个配置好的factory实例用于execing容器
func loadFactory(context *cli.Context) (libcontainer.Factory, error) {
	root := context.GlobalString("root")
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	// We default to cgroupfs, and can only use systemd if the system is a
	// systemd box.
	// 创建cgroup manager，默认为systemd-cgroup
	cgroupManager := libcontainer.Cgroupfs
	if context.GlobalBool("systemd-cgroup") {
		if systemd.UseSystemd() {
			cgroupManager = libcontainer.SystemdCgroups
		} else {
			return nil, fmt.Errorf("systemd cgroup flag passed, but systemd support for managing cgroups is not available")
		}
	}

	intelRdtManager := libcontainer.IntelRdtFs
	if !intelrdt.IsEnabled() {
		intelRdtManager = nil
	}

	// We resolve the paths for {newuidmap,newgidmap} from the context of runc,
	// to avoid doing a path lookup in the nsexec context. TODO: The binary
	// names are not currently configurable.
	// newuidmap和newgidmap的绝对路径
	newuidmap, err := exec.LookPath("newuidmap")
	if err != nil {
		newuidmap = ""
	}
	newgidmap, err := exec.LookPath("newgidmap")
	if err != nil {
		newgidmap = ""
	}

	return libcontainer.New(abs, cgroupManager, intelRdtManager,
		libcontainer.CriuPath(context.GlobalString("criu")),
		libcontainer.NewuidmapPath(newuidmap),
		libcontainer.NewgidmapPath(newgidmap))
}

// getContainer returns the specified container instance by loading it from state
// with the default factory.
func getContainer(context *cli.Context) (libcontainer.Container, error) {
	id := context.Args().First()
	if id == "" {
		return nil, errEmptyID
	}
	factory, err := loadFactory(context)
	if err != nil {
		return nil, err
	}
	return factory.Load(id)
}

func fatalf(t string, v ...interface{}) {
	fatal(fmt.Errorf(t, v...))
}

func getDefaultImagePath(context *cli.Context) string {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return filepath.Join(cwd, "checkpoint")
}

// newProcess returns a new libcontainer Process with the arguments from the
// spec and stdio from the current process.
// newProcess返回一个新的libcontainer Process，根据参数spec以及当前进程的stdio
func newProcess(p specs.Process) (*libcontainer.Process, error) {
	lp := &libcontainer.Process{
		Args: p.Args,
		Env:  p.Env,
		// TODO: fix libcontainer's API to better support uid/gid in a typesafe way.
		User:            fmt.Sprintf("%d:%d", p.User.UID, p.User.GID),
		Cwd:             p.Cwd,
		Label:           p.SelinuxLabel,
		NoNewPrivileges: &p.NoNewPrivileges,
		AppArmorProfile: p.ApparmorProfile,
	}

	if p.ConsoleSize != nil {
		lp.ConsoleWidth = uint16(p.ConsoleSize.Width)
		lp.ConsoleHeight = uint16(p.ConsoleSize.Height)
	}

	if p.Capabilities != nil {
		lp.Capabilities = &configs.Capabilities{}
		lp.Capabilities.Bounding = p.Capabilities.Bounding
		lp.Capabilities.Effective = p.Capabilities.Effective
		lp.Capabilities.Inheritable = p.Capabilities.Inheritable
		lp.Capabilities.Permitted = p.Capabilities.Permitted
		lp.Capabilities.Ambient = p.Capabilities.Ambient
	}
	for _, gid := range p.User.AdditionalGids {
		lp.AdditionalGroups = append(lp.AdditionalGroups, strconv.FormatUint(uint64(gid), 10))
	}
	for _, rlimit := range p.Rlimits {
		// 转换容器的资源配置
		rl, err := createLibContainerRlimit(rlimit)
		if err != nil {
			return nil, err
		}
		lp.Rlimits = append(lp.Rlimits, rl)
	}
	return lp, nil
}

func destroy(container libcontainer.Container) {
	if err := container.Destroy(); err != nil {
		logrus.Error(err)
	}
}

// setupIO modifies the given process config according to the options.
// setupIO根据options修改给定的process config
func setupIO(process *libcontainer.Process, rootuid, rootgid int, createTTY, detach bool, sockpath string) (*tty, error) {
	if createTTY {
		// 如果创建tty
		process.Stdin = nil
		process.Stdout = nil
		process.Stderr = nil
		t := &tty{}
		if !detach {
			// 如果不是detach，创建名为"console"的SocketPair
			parent, child, err := utils.NewSockPair("console")
			if err != nil {
				return nil, err
			}
			// 将process的ConsoleSocket设置为child
			process.ConsoleSocket = child
			t.postStart = append(t.postStart, parent, child)
			t.consoleC = make(chan error, 1)
			go func() {
				if err := t.recvtty(process, parent); err != nil {
					t.consoleC <- err
				}
				t.consoleC <- nil
			}()
		} else {
			// the caller of runc will handle receiving the console master
			// 如果设置了detach
			// runc的调用者会负责处理接收console master
			conn, err := net.Dial("unix", sockpath)
			if err != nil {
				return nil, err
			}
			uc, ok := conn.(*net.UnixConn)
			if !ok {
				return nil, fmt.Errorf("casting to UnixConn failed")
			}
			t.postStart = append(t.postStart, uc)
			socket, err := uc.File()
			if err != nil {
				return nil, err
			}
			t.postStart = append(t.postStart, socket)
			process.ConsoleSocket = socket
		}
		return t, nil
	}
	// when runc will detach the caller provides the stdio to runc via runc's 0,1,2
	// and the container's process inherits runc's stdio.
	// 指定了detach，则会继承runc的stdio
	if detach {
		// 将os.Stdio直接赋值给process.Stdio
		if err := inheritStdio(process); err != nil {
			return nil, err
		}
		return &tty{}, nil
	}
	// 没指定tty也没指定detach
	return setupProcessPipes(process, rootuid, rootgid)
}

// createPidFile creates a file with the processes pid inside it atomically
// it creates a temp file with the paths filename + '.' infront of it
// then renames the file
func createPidFile(path string, process *libcontainer.Process) error {
	pid, err := process.Pid()
	if err != nil {
		return err
	}
	var (
		tmpDir  = filepath.Dir(path)
		tmpName = filepath.Join(tmpDir, fmt.Sprintf(".%s", filepath.Base(path)))
	)
	f, err := os.OpenFile(tmpName, os.O_RDWR|os.O_CREATE|os.O_EXCL|os.O_SYNC, 0666)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "%d", pid)
	f.Close()
	if err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// XXX: Currently we autodetect rootless mode.
func isRootless() bool {
	return os.Geteuid() != 0
}

func createContainer(context *cli.Context, id string, spec *specs.Spec) (libcontainer.Container, error) {
	// 创建libcontainer config
	config, err := specconv.CreateLibcontainerConfig(&specconv.CreateOpts{
		CgroupName:       id,
		UseSystemdCgroup: context.GlobalBool("systemd-cgroup"),
		NoPivotRoot:      context.Bool("no-pivot"),
		NoNewKeyring:     context.Bool("no-new-keyring"),
		Spec:             spec,
		// 判断当前进程是否为root
		Rootless:         isRootless(),
	})
	if err != nil {
		return nil, err
	}

	factory, err := loadFactory(context)
	if err != nil {
		return nil, err
	}
	return factory.Create(id, config)
}

type runner struct {
	enableSubreaper bool
	shouldDestroy   bool
	detach          bool
	listenFDs       []*os.File
	preserveFDs     int
	pidFile         string
	consoleSocket   string
	// runner保存了libcontainer格式的Container
	container       libcontainer.Container
	// runner保存了要采取的action，
	action          CtAct
	notifySocket    *notifySocket
	criuOpts        *libcontainer.CriuOpts
}

func (r *runner) run(config *specs.Process) (int, error) {
	if err := r.checkTerminal(config); err != nil {
		r.destroy()
		return -1, err
	}
	// 将spec的Process转换为libcontainer的Process
	process, err := newProcess(*config)
	if err != nil {
		r.destroy()
		return -1, err
	}
	if len(r.listenFDs) > 0 {
		// 设置listen fds
		process.Env = append(process.Env, fmt.Sprintf("LISTEN_FDS=%d", len(r.listenFDs)), "LISTEN_PID=1")
		// 添加extra files
		process.ExtraFiles = append(process.ExtraFiles, r.listenFDs...)
	}
	baseFd := 3 + len(process.ExtraFiles)
	for i := baseFd; i < baseFd+r.preserveFDs; i++ {
		// 将PreserveFD加入extra files
		process.ExtraFiles = append(process.ExtraFiles, os.NewFile(uintptr(i), "PreserveFD:"+strconv.Itoa(i)))
	}
	rootuid, err := r.container.Config().HostRootUID()
	if err != nil {
		r.destroy()
		return -1, err
	}
	rootgid, err := r.container.Config().HostRootGID()
	if err != nil {
		r.destroy()
		return -1, err
	}
	var (
		// 当action为CREATE时，默认为detach
		detach = r.detach || (r.action == CT_ACT_CREATE)
	)
	// Setting up IO is a two stage process. We need to modify process to deal
	// with detaching containers, and then we get a tty after the container has
	// started.
	// 设置IO分为两个阶段
	// 我们需要修改process用于处理detaching container
	// 之后我们在容器启动之后获取一个tty
	handler := newSignalHandler(r.enableSubreaper, r.notifySocket)
	// 设置process的Stdin, Stdout和Stderr
	tty, err := setupIO(process, rootuid, rootgid, config.Terminal, detach, r.consoleSocket)
	if err != nil {
		r.destroy()
		return -1, err
	}
	defer tty.Close()

	switch r.action {
	// 根据action，创建，恢复或者运行容器
	case CT_ACT_CREATE:
		err = r.container.Start(process)
	case CT_ACT_RESTORE:
		err = r.container.Restore(process, r.criuOpts)
	case CT_ACT_RUN:
		err = r.container.Run(process)
	default:
		panic("Unknown action")
	}
	if err != nil {
		r.destroy()
		return -1, err
	}
	if err := tty.waitConsole(); err != nil {
		r.terminate(process)
		r.destroy()
		return -1, err
	}
	if err = tty.ClosePostStart(); err != nil {
		r.terminate(process)
		r.destroy()
		return -1, err
	}
	if r.pidFile != "" {
		if err = createPidFile(r.pidFile, process); err != nil {
			r.terminate(process)
			r.destroy()
			return -1, err
		}
	}
	status, err := handler.forward(process, tty, detach)
	if err != nil {
		r.terminate(process)
	}
	if detach {
		// 如果为detach，直接返回
		return 0, nil
	}
	r.destroy()
	return status, err
}

func (r *runner) destroy() {
	if r.shouldDestroy {
		destroy(r.container)
	}
}

func (r *runner) terminate(p *libcontainer.Process) {
	_ = p.Signal(unix.SIGKILL)
	_, _ = p.Wait()
}

func (r *runner) checkTerminal(config *specs.Process) error {
	// 当action为CT_ACT_CREATE时，detach也为true
	detach := r.detach || (r.action == CT_ACT_CREATE)
	// Check command-line for sanity.
	// 如果容器设置了detach并且没有指定console，则不能获取tty
	if detach && config.Terminal && r.consoleSocket == "" {
		return fmt.Errorf("cannot allocate tty if runc will detach without setting console socket")
	}
	// 如果容器没有detach或者没有设置terminal，就不能设置console
	if (!detach || !config.Terminal) && r.consoleSocket != "" {
		return fmt.Errorf("cannot use console socket if runc will not detach or allocate tty")
	}
	return nil
}

// spec中的Cwd不能为空且必须为绝对路径
// 且spec的Args不能为空
func validateProcessSpec(spec *specs.Process) error {
	if spec.Cwd == "" {
		return fmt.Errorf("Cwd property must not be empty")
	}
	if !filepath.IsAbs(spec.Cwd) {
		return fmt.Errorf("Cwd must be an absolute path")
	}
	if len(spec.Args) == 0 {
		return fmt.Errorf("args must not be empty")
	}
	return nil
}

type CtAct uint8

const (
	CT_ACT_CREATE CtAct = iota + 1
	CT_ACT_RUN
	CT_ACT_RESTORE
)

func startContainer(context *cli.Context, spec *specs.Spec, action CtAct, criuOpts *libcontainer.CriuOpts) (int, error) {
	id := context.Args().First()
	if id == "" {
		return -1, errEmptyID
	}

	// 创建notify socket，如果指定了"NOTIFY_SOCKET"
	notifySocket := newNotifySocket(context, os.Getenv("NOTIFY_SOCKET"), id)
	if notifySocket != nil {
		notifySocket.setupSpec(context, spec)
	}

	// 创建container数据结构
	container, err := createContainer(context, id, spec)
	if err != nil {
		return -1, err
	}

	if notifySocket != nil {
		// 启动notify socket进行监听
		err := notifySocket.setupSocket()
		if err != nil {
			return -1, err
		}
	}

	// Support on-demand socket activation by passing file descriptors into the container init process.
	// 通过将文件描述符传递给容器的init process来支持on-demand套接字激活
	listenFDs := []*os.File{}
	if os.Getenv("LISTEN_FDS") != "" {
		listenFDs = activation.Files(false)
	}
	// 创建runner对象
	r := &runner{
		enableSubreaper: !context.Bool("no-subreaper"),
		// 需要destroy
		shouldDestroy:   true,
		container:       container,
		listenFDs:       listenFDs,
		notifySocket:    notifySocket,
		consoleSocket:   context.String("console-socket"),
		detach:          context.Bool("detach"),
		pidFile:         context.String("pid-file"),
		preserveFDs:     context.Int("preserve-fds"),
		// Create，Run还是Restore
		action:          action,
		criuOpts:        criuOpts,
	}
	return r.run(spec.Process)
}
