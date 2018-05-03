package libcontainer

import (
	"github.com/opencontainers/runc/libcontainer/configs"
)

type Factory interface {
	// Creates a new container with the given id and starts the initial process inside it.
	// 用给定的id创建一个新的容器，并且在其中启动initial process
	// id must be a string containing only letters, digits and underscores and must contain
	// between 1 and 1024 characters, inclusive.
	//
	// The id must not already be in use by an existing container. Containers created using
	// a factory with the same path (and filesystem) must have distinct ids.
	//
	// Returns the new container with a running process.
	// 返回一个有着running process的新的容器
	//
	// errors:
	// IdInUse - id is already in use by a container
	// InvalidIdFormat - id has incorrect format
	// ConfigInvalid - config is invalid
	// Systemerror - System error
	//
	// On error, any partially created container parts are cleaned up (the operation is atomic).
	// 当发生错误时，任何部分被创建的容器都会被清除（该操作是原子的）
	Create(id string, config *configs.Config) (Container, error)

	// Load takes an ID for an existing container and returns the container information
	// from the state.  This presents a read only view of the container.
	// Load根据一个已经存在的容器的ID，返回容器的只读状态信息
	//
	// errors:
	// Path does not exist
	// System error
	Load(id string) (Container, error)

	// StartInitialization is an internal API to libcontainer used during the reexec of the
	// container.
	// StartInitialization是libcontainer一个内部的API，用于容器的reexec
	//
	// Errors:
	// Pipe connection error
	// System error
	StartInitialization() error

	// Type returns info string about factory type (e.g. lxc, libcontainer...)
	// Type返回一个info字符串，关于factory的类型（lxc, libcontainer等）
	Type() string
}
