// automatically generated by stateify.

package fdpipe

import (
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/state"
)

func (p *pipeOperations) StateTypeName() string {
	return "pkg/sentry/fs/fdpipe.pipeOperations"
}

func (p *pipeOperations) StateFields() []string {
	return []string{
		"Queue",
		"flags",
		"opener",
		"readAheadBuffer",
	}
}

// +checklocksignore
func (p *pipeOperations) StateSave(stateSinkObject state.Sink) {
	p.beforeSave()
	var flagsValue fs.FileFlags
	flagsValue = p.saveFlags()
	stateSinkObject.SaveValue(1, flagsValue)
	stateSinkObject.Save(0, &p.Queue)
	stateSinkObject.Save(2, &p.opener)
	stateSinkObject.Save(3, &p.readAheadBuffer)
}

// +checklocksignore
func (p *pipeOperations) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &p.Queue)
	stateSourceObject.LoadWait(2, &p.opener)
	stateSourceObject.Load(3, &p.readAheadBuffer)
	stateSourceObject.LoadValue(1, new(fs.FileFlags), func(y interface{}) { p.loadFlags(y.(fs.FileFlags)) })
	stateSourceObject.AfterLoad(p.afterLoad)
}

func init() {
	state.Register((*pipeOperations)(nil))
}
