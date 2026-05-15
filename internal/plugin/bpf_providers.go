package plugin

import "github.com/cilium/ebpf"

// BPFCollectionProvider bridges bpf2go-generated loaders from package main.
type BPFCollectionProvider interface {
	LoadAndAssign(obj interface{}, opts *ebpf.CollectionOptions) error
}

// PolicyControl is implemented by plugins with runtime enable switches.
type PolicyControl interface {
	IsEnabled() bool
	SetEnabled(bool) error
}
