package pcapng

import (
	"sync"
	"sync/atomic"
)

// cbpool maps opaque uintptr handles to Go callback functions so that C
// trampolines can reach them via a void *userdata pointer.

var (
	cbSeq    atomic.Uintptr
	cbMap    sync.Map
)

func cbStore(fn any) uintptr {
	h := cbSeq.Add(1)
	cbMap.Store(h, fn)
	return h
}

func cbLoad(h uintptr) any {
	v, _ := cbMap.Load(h)
	return v
}

func cbDelete(h uintptr) {
	cbMap.Delete(h)
}
