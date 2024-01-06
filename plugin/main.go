package main

import (
	lsm "github.com/dwindsor/lsm-plugin/pkg"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

const (
	PluginID          uint32 = 37
	PluginName               = "lsm"
	PluginDescription        = "Events from Linux Security Modules"
	PluginContact            = "github.com/falcosecurity/plugins/"
	PluginVersion            = "0.1.0"
	PluginEventSource        = "lsm"
)

func init() {
	plugins.SetFactory(func() plugins.Plugin {
		p := &lsm.Plugin{}
		p.SetInfo(
			PluginID,
			PluginName,
			PluginDescription,
			PluginContact,
			PluginVersion,
			PluginEventSource,
		)
		extractor.Register(p)
		source.Register(p)
		return p
	})
}

func main() {}
