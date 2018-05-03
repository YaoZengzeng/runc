package libcontainer

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/opencontainers/runc/libcontainer/utils"
)

type syncType string

// Constants that are used for synchronisation between the parent and child
// during container setup. They come in pairs (with procError being a generic
// response which is followed by a &genericError).
// 在容器创建期间，用于同步parent和child之间的常量，并且它们总是成对出现的
//
// [  child  ] <-> [   parent   ]
//
// 先执行hook
// procHooks   --> [run hooks]
//             <-- procResume
//
// 再执行console
// procConsole -->
//             <-- procConsoleReq
//  [send(fd)] --> [recv(fd)]
//             <-- procConsoleAck
//
// 最后procReady
// procReady   --> [final setup]
//             <-- procRun
const (
	procError  syncType = "procError"
	procReady  syncType = "procReady"
	procRun    syncType = "procRun"
	procHooks  syncType = "procHooks"
	procResume syncType = "procResume"
)

type syncT struct {
	Type syncType `json:"type"`
}

// writeSync is used to write to a synchronisation pipe. An error is returned
// if there was a problem writing the payload.
// writeSync负责写入同步的管道
func writeSync(pipe io.Writer, sync syncType) error {
	if err := utils.WriteJSON(pipe, syncT{sync}); err != nil {
		return err
	}
	return nil
}

// readSync is used to read from a synchronisation pipe. An error is returned
// if we got a genericError, the pipe was closed, or we got an unexpected flag.
func readSync(pipe io.Reader, expected syncType) error {
	var procSync syncT
	if err := json.NewDecoder(pipe).Decode(&procSync); err != nil {
		if err == io.EOF {
			return fmt.Errorf("parent closed synchronisation channel")
		}

		if procSync.Type == procError {
			var ierr genericError

			if err := json.NewDecoder(pipe).Decode(&ierr); err != nil {
				return fmt.Errorf("failed reading error from parent: %v", err)
			}

			return &ierr
		}

		if procSync.Type != expected {
			return fmt.Errorf("invalid synchronisation flag from parent")
		}
	}
	return nil
}

// parseSync runs the given callback function on each syncT received from the
// child. It will return once io.EOF is returned from the given pipe.
// parseSync在每次从child接收到syncT的时候，就调用一次给定的回调函数
func parseSync(pipe io.Reader, fn func(*syncT) error) error {
	dec := json.NewDecoder(pipe)
	for {
		var sync syncT
		if err := dec.Decode(&sync); err != nil {
			// 当对端关闭，读取到EOF时，退出sync
			if err == io.EOF {
				break
			}
			return err
		}

		// We handle this case outside fn for cleanliness reasons.
		var ierr *genericError
		if sync.Type == procError {
			if err := dec.Decode(&ierr); err != nil && err != io.EOF {
				return newSystemErrorWithCause(err, "decoding proc error from init")
			}
			if ierr != nil {
				return ierr
			}
			// Programmer error.
			panic("No error following JSON procError payload.")
		}

		if err := fn(&sync); err != nil {
			return err
		}
	}
	return nil
}
