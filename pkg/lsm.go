package lsm

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"bufio"

	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

var (
	ID          uint32
	Name        string
	Description string
	Contact     string
	Version     string
	EventSource string
)

type PluginConfig struct {
	FlushInterval uint64 `json:"flushInterval" jsonschema:"description=Flush Interval in ms (Default: 30)"`
}

// Plugin represents our plugin
type Plugin struct {
	plugins.BasePlugin
	Config                 PluginConfig
	lastLsmEventMessage    LsmMessage 
	lastLsmEventNum	       uint64		
}

type LsmMessage struct {
	Etype	string	`json:"etype"`
	SecurityHook	string	`json:"securityhook"`
	Path	string	`json:"path"`
	Device	string	`json:"device"`
	Inode	string	`json:"inode"`
	Username	string	`json:"username"`
	Group		string	`json:"group"`
}

// setDefault is used to set default values before mapping with InitSchema()
func (p *PluginConfig) setDefault() {
	p.FlushInterval = 30
}

// SetInfo is used to set the Info of the plugin
func (p *Plugin) SetInfo(id uint32, name, description, contact, version, eventSource string) {
	ID = id
	Name = name
	Contact = contact
	Version = version
	EventSource = eventSource
}

// Info displays information of the plugin to Falco plugin framework
func (p *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          ID,
		Name:        Name,
		Description: Description,
		Contact:     Contact,
		Version:     Version,
		EventSource: EventSource,
	}
}

// InitSchema map the configuration values with Plugin structure through JSONSchema tags
func (p *Plugin) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true, // all properties are optional by default
		AllowAdditionalProperties:  true, // unrecognized properties don't cause a parsing failures
	}
	if schema, err := reflector.Reflect(&PluginConfig{}).MarshalJSON(); err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}

// Init is called by the Falco plugin framework as first entry,
// we use it for setting default configuration values and mapping
// values from `init_config` (json format for this plugin)
func (p *Plugin) Init(config string) error {
	p.Config.setDefault()
	return json.Unmarshal([]byte(config), &p.Config)
}

// Fields exposes to Falco plugin framework all availables fields for this plugin
func (p *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "lsm.etype", Desc: "Type of the event"},
		{Type: "string", Name: "lsm.hook", Desc: "Security hook providing this telemetry"},
		{Type: "string", Name: "lsm.file.path", Desc: "Absolute path of the file in this hook"},
		{Type: "string", Name: "lsm.file.device", Desc: "Device number of file in lsm.path"},
		{Type: "string", Name: "lsm.file.inode", Desc: "Inode of the file in lsm.path"},
		{Type: "string", Name: "lsm.user.uid", Desc: "Uid of user performing this action"},
		{Type: "string", Name: "lsm.user.gid", Desc: "Gid of user performing this action"},
	}
}

// Extract allows Falco plugin framework to get values for all available fields
func (p *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	msg := p.lastLsmEventMessage

	// For avoiding to Unmarshal the same message for each field to extract
	// we store it with its EventNum. When it's a new event with a new message, we
	// update the Plugin struct.
	if evt.EventNum() != p.lastLsmEventNum {
		rawData, err := ioutil.ReadAll(evt.Reader())
		jsonstr := string(rawData)

		if err != nil {
			fmt.Println(err.Error())
			return err
		}

		err = json.Unmarshal([]byte(jsonstr), &msg)
		if err != nil {
			return err
		}

		p.lastLsmEventMessage = msg
		p.lastLsmEventNum = evt.EventNum()
	}

	switch req.Field() {
	case "lsm.etype":
		req.SetValue(msg.Etype)
	case "lsm.hook":
		req.SetValue(msg.SecurityHook)
	case "lsm.file.path":
		req.SetValue(msg.Path)
	case "lsm.file.device":
		req.SetValue(msg.Device)
	case "lsm.file.inode":
		req.SetValue(msg.Inode)
	case "lsm.user.uid":
		req.SetValue(msg.Username)
	case "lsm.user.gid":
		req.SetValue(msg.Group)
	default:
		return fmt.Errorf("no known field: %s", req.Field())
	}

	return nil
}

func close_fn() {
	os.Exit(0)
}

// Open is called by Falco plugin framework for opening a stream of events, we call that an instance
func (Plugin *Plugin) Open(params string) (source.Instance, error) {
	eventC := make(chan source.PushEvent)
	// launch an async worker that listens for lsm events and pushes them
	// to the event channel
	go func() {
		defer close(eventC)
		
		cmd := exec.Command("/usr/bin/lsm-rs");
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			fmt.Println("Error launching lsm-rs:", err)
			return
		}
		cmd.Start()

		defer cmd.Wait();

		reader := bufio.NewReader(stdout)
		for {
			eventjson, err := reader.ReadString('\n')
			if err != nil {
				return
			}

			b := []byte(eventjson)
			eventC <- source.PushEvent{Data: b}
		}
	}()
	return source.NewPushInstance(eventC, source.WithInstanceClose(close_fn))
}

// String represents the raw value of on event
// (not currently used by Falco plugin framework, only there for future usage)
func (Plugin *Plugin) String(in io.ReadSeeker) (string, error) {
	evtBytes, err := ioutil.ReadAll(in)
	if err != nil {
		return "", err
	}
	evtStr := string(evtBytes)
	return fmt.Sprintf("%v", evtStr), nil
}
