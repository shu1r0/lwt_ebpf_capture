package ebpf

import (
	_ "unsafe"

	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go capture ../../ebpf/lwt_capture.c -- -I../../ebpf/ -I/usr/include/

type EBpfObjects struct {
	captureObjects
}

func NewEBpfObjects(options *ebpf.CollectionOptions) (*EBpfObjects, error) {
	driver := &EBpfObjects{}

	spec, err := loadCapture()
	if err != nil {
		return nil, err
	}

	if err := spec.LoadAndAssign(driver, options); err != nil {
		return nil, err
	}
	return driver, nil
}
