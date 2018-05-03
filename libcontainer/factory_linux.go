// +build linux

package libcontainer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fs"
	"github.com/opencontainers/runc/libcontainer/cgroups/systemd"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/configs/validate"
	"github.com/opencontainers/runc/libcontainer/intelrdt"
	"github.com/opencontainers/runc/libcontainer/mount"
	"github.com/opencontainers/runc/libcontainer/utils"

	"golang.org/x/sys/unix"
)

const (
	stateFilename    = "state.json"
	execFifoFilename = "exec.fifo"
)

var idRegex = regexp.MustCompile(`^[\w+-\.]+$`)

// InitArgs returns an options func to configure a LinuxFactory with the
// provided init binary path and arguments.
func InitArgs(args ...string) func(*LinuxFactory) error {
	return func(l *LinuxFactory) (err error) {
		if len(args) > 0 {
			// Resolve relative paths to ensure that its available
			// after directory changes.
			if args[0], err = filepath.Abs(args[0]); err != nil {
				return newGenericError(err, ConfigInvalid)
			}
		}

		l.InitArgs = args
		return nil
	}
}

// SystemdCgroups is an options func to configure a LinuxFactory to return
// containers that use systemd to create and manage cgroups.
func SystemdCgroups(l *LinuxFactory) error {
	l.NewCgroupsManager = func(config *configs.Cgroup, paths map[string]string) cgroups.Manager {
		return &systemd.Manager{
			Cgroups: config,
			Paths:   paths,
		}
	}
	return nil
}

// Cgroupfs is an options func to configure a LinuxFactory to return
// containers that use the native cgroups filesystem implementation to
// create and manage cgroups.
// Cgroupfs是一个opions func用于配置LinuxFactory
// 通过原生的cgroups filesystem的实现来创建和管理cgroups
func Cgroupfs(l *LinuxFactory) error {
	l.NewCgroupsManager = func(config *configs.Cgroup, paths map[string]string) cgroups.Manager {
		return &fs.Manager{
			Cgroups: config,
			Paths:   paths,
		}
	}
	return nil
}

// IntelRdtfs is an options func to configure a LinuxFactory to return
// containers that use the Intel RDT "resource control" filesystem to
// create and manage Intel Xeon platform shared resources (e.g., L3 cache).
func IntelRdtFs(l *LinuxFactory) error {
	l.NewIntelRdtManager = func(config *configs.Config, id string, path string) intelrdt.Manager {
		return &intelrdt.IntelRdtManager{
			Config: config,
			Id:     id,
			Path:   path,
		}
	}
	return nil
}

// TmpfsRoot is an option func to mount LinuxFactory.Root to tmpfs.
func TmpfsRoot(l *LinuxFactory) error {
	mounted, err := mount.Mounted(l.Root)
	if err != nil {
		return err
	}
	if !mounted {
		if err := unix.Mount("tmpfs", l.Root, "tmpfs", 0, ""); err != nil {
			return err
		}
	}
	return nil
}

// CriuPath returns an option func to configure a LinuxFactory with the
// provided criupath
func CriuPath(criupath string) func(*LinuxFactory) error {
	return func(l *LinuxFactory) error {
		l.CriuPath = criupath
		return nil
	}
}

// New returns a linux based container factory based in the root directory and
// configures the factory with the provided option funcs.
// New返回一个linux based容器的factory，基于root directory
// 以及给定的option funcs用于配置factory
func New(root string, options ...func(*LinuxFactory) error) (Factory, error) {
	if root != "" {
		if err := os.MkdirAll(root, 0700); err != nil {
			return nil, newGenericError(err, SystemError)
		}
	}
	l := &LinuxFactory{
		Root:      root,
		InitPath:  "/proc/self/exe",
		InitArgs:  []string{os.Args[0], "init"},
		Validator: validate.New(),
		CriuPath:  "criu",
	}
	Cgroupfs(l)
	for _, opt := range options {
		if opt == nil {
			continue
		}
		if err := opt(l); err != nil {
			return nil, err
		}
	}
	return l, nil
}

// LinuxFactory implements the default factory interface for linux based systems.
// LinuxFactory实现了基于linux的系统的默认的factory interface
type LinuxFactory struct {
	// Root directory for the factory to store state.
	// factory用于存储状态的Root目录
	Root string

	// InitPath is the path for calling the init responsibilities for spawning
	// a container.
	// InitPath是生成容器时，用于完成初始化责任的路径
	InitPath string

	// InitArgs are arguments for calling the init responsibilities for spawning
	// a container.
	// InitArgs是生成容器时，用于完成初始化责任的参数
	InitArgs []string

	// CriuPath is the path to the criu binary used for checkpoint and restore of
	// containers.
	CriuPath string

	// New{u,g}uidmapPath is the path to the binaries used for mapping with
	// rootless containers.
	// New{u,g}uidmapPath是用于rootless container进行mapping的二进制文件的目录
	NewuidmapPath string
	NewgidmapPath string

	// Validator provides validation to container configurations.
	// Validator用于检测容器的陪住是否正确
	Validator validate.Validator

	// NewCgroupsManager returns an initialized cgroups manager for a single container.
	// NewCgroupsManager为单个容器返回一个已经初始化完成的cgroups manager
	NewCgroupsManager func(config *configs.Cgroup, paths map[string]string) cgroups.Manager

	// NewIntelRdtManager returns an initialized Intel RDT manager for a single container.
	NewIntelRdtManager func(config *configs.Config, id string, path string) intelrdt.Manager
}

// Create创建一个容器实例
func (l *LinuxFactory) Create(id string, config *configs.Config) (Container, error) {
	if l.Root == "" {
		return nil, newGenericError(fmt.Errorf("invalid root"), ConfigInvalid)
	}
	if err := l.validateID(id); err != nil {
		return nil, err
	}
	if err := l.Validator.Validate(config); err != nil {
		return nil, newGenericError(err, ConfigInvalid)
	}
	containerRoot := filepath.Join(l.Root, id)
	if _, err := os.Stat(containerRoot); err == nil {
		// 根据容器的根目录是否存在，来判断容器是否被创建
		return nil, newGenericError(fmt.Errorf("container with id exists: %v", id), IdInUse)
	} else if !os.IsNotExist(err) {
		return nil, newGenericError(err, SystemError)
	}
	if err := os.MkdirAll(containerRoot, 0711); err != nil {
		return nil, newGenericError(err, SystemError)
	}
	if err := os.Chown(containerRoot, unix.Geteuid(), unix.Getegid()); err != nil {
		return nil, newGenericError(err, SystemError)
	}
	c := &linuxContainer{
		id:            id,
		root:          containerRoot,
		config:        config,
		initPath:      l.InitPath,
		initArgs:      l.InitArgs,
		criuPath:      l.CriuPath,
		newuidmapPath: l.NewuidmapPath,
		newgidmapPath: l.NewgidmapPath,
		// 创建适当的cgroup manager
		cgroupManager: l.NewCgroupsManager(config.Cgroups, nil),
	}
	if intelrdt.IsEnabled() {
		c.intelRdtManager = l.NewIntelRdtManager(config, id, "")
	}
	// 设置容器的初始状态为stopped
	c.state = &stoppedState{c: c}
	return c, nil
}

func (l *LinuxFactory) Load(id string) (Container, error) {
	if l.Root == "" {
		return nil, newGenericError(fmt.Errorf("invalid root"), ConfigInvalid)
	}
	containerRoot := filepath.Join(l.Root, id)
	state, err := l.loadState(containerRoot, id)
	if err != nil {
		return nil, err
	}
	r := &nonChildProcess{
		processPid:       state.InitProcessPid,
		processStartTime: state.InitProcessStartTime,
		fds:              state.ExternalDescriptors,
	}
	c := &linuxContainer{
		initProcess:          r,
		initProcessStartTime: state.InitProcessStartTime,
		id:                   id,
		config:               &state.Config,
		initPath:             l.InitPath,
		initArgs:             l.InitArgs,
		criuPath:             l.CriuPath,
		newuidmapPath:        l.NewuidmapPath,
		newgidmapPath:        l.NewgidmapPath,
		cgroupManager:        l.NewCgroupsManager(state.Config.Cgroups, state.CgroupPaths),
		root:                 containerRoot,
		created:              state.Created,
	}
	c.state = &loadedState{c: c}
	if err := c.refreshState(); err != nil {
		return nil, err
	}
	if intelrdt.IsEnabled() {
		c.intelRdtManager = l.NewIntelRdtManager(&state.Config, id, state.IntelRdtPath)
	}
	return c, nil
}

func (l *LinuxFactory) Type() string {
	return "libcontainer"
}

// StartInitialization loads a container by opening the pipe fd from the parent to read the configuration and state
// This is a low level implementation detail of the reexec and should not be consumed externally
// StartInitialization通过打开来自父进程的pipe fd来读取配置和状态，从而加载容器
func (l *LinuxFactory) StartInitialization() (err error) {
	var (
		pipefd, fifofd int
		consoleSocket  *os.File
		envInitPipe    = os.Getenv("_LIBCONTAINER_INITPIPE")
		envFifoFd      = os.Getenv("_LIBCONTAINER_FIFOFD")
		envConsole     = os.Getenv("_LIBCONTAINER_CONSOLE")
	)

	// Get the INITPIPE.
	// pipe为INITPIPE
	pipefd, err = strconv.Atoi(envInitPipe)
	if err != nil {
		return fmt.Errorf("unable to convert _LIBCONTAINER_INITPIPE=%s to int: %s", envInitPipe, err)
	}

	var (
		pipe = os.NewFile(uintptr(pipefd), "pipe")
		it   = initType(os.Getenv("_LIBCONTAINER_INITTYPE"))
	)
	defer pipe.Close()

	// Only init processes have FIFOFD.
	// 只有init进程有FIFOFD
	fifofd = -1
	if it == initStandard {
		if fifofd, err = strconv.Atoi(envFifoFd); err != nil {
			return fmt.Errorf("unable to convert _LIBCONTAINER_FIFOFD=%s to int: %s", envFifoFd, err)
		}
	}

	if envConsole != "" {
		console, err := strconv.Atoi(envConsole)
		if err != nil {
			return fmt.Errorf("unable to convert _LIBCONTAINER_CONSOLE=%s to int: %s", envConsole, err)
		}
		// 打开console socket
		consoleSocket = os.NewFile(uintptr(console), "console-socket")
		defer consoleSocket.Close()
	}

	// clear the current process's environment to clean any libcontainer
	// specific env vars.
	// 清除当前进程的环境变量，从而清除任何libcontainer相关的环境变量
	os.Clearenv()

	defer func() {
		// We have an error during the initialization of the container's init,
		// send it back to the parent process in the form of an initError.
		// 如果在容器的init的初始化过程中遇到了错误
		// 就以initError的形式返回给父进程
		if werr := utils.WriteJSON(pipe, syncT{procError}); werr != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if werr := utils.WriteJSON(pipe, newSystemError(err)); werr != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}()
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("panic from initialization: %v, %v", e, string(debug.Stack()))
		}
	}()

	i, err := newContainerInit(it, pipe, consoleSocket, fifofd)
	if err != nil {
		return err
	}

	// If Init succeeds, syscall.Exec will not return, hence none of the defers will be called.
	// 如果Init成功，syscall.Exec不会返回，因此不会有defer函数执行
	return i.Init()
}

func (l *LinuxFactory) loadState(root, id string) (*State, error) {
	f, err := os.Open(filepath.Join(root, stateFilename))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, newGenericError(fmt.Errorf("container %q does not exist", id), ContainerNotExists)
		}
		return nil, newGenericError(err, SystemError)
	}
	defer f.Close()
	var state *State
	if err := json.NewDecoder(f).Decode(&state); err != nil {
		return nil, newGenericError(err, SystemError)
	}
	return state, nil
}

func (l *LinuxFactory) validateID(id string) error {
	if !idRegex.MatchString(id) {
		return newGenericError(fmt.Errorf("invalid id format: %v", id), InvalidIdFormat)
	}

	return nil
}

// NewuidmapPath returns an option func to configure a LinuxFactory with the
// provided ..
func NewuidmapPath(newuidmapPath string) func(*LinuxFactory) error {
	return func(l *LinuxFactory) error {
		l.NewuidmapPath = newuidmapPath
		return nil
	}
}

// NewgidmapPath returns an option func to configure a LinuxFactory with the
// provided ..
func NewgidmapPath(newgidmapPath string) func(*LinuxFactory) error {
	return func(l *LinuxFactory) error {
		l.NewgidmapPath = newgidmapPath
		return nil
	}
}
