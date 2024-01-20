// This file implements conversion from old (Go 1.11–Go 1.21) traces to the Go
// 1.22 format.
//
// Most events have direct equivalents in 1.22, at worst requiring arguments to
// be reordered. Some events, such as GoWaiting need to wait for follow-up
// events to determine the correct translation. GoSyscall, which is an
// instantaneous event, gets turned into a 1 ns long pair of
// GoSyscallStart+GoSyscallEnd, unless we observe a GoSysBlock, in which case we
// emit a GoSyscallStart+GoSyscallEndBlocked pair with the correct duration
// (i.e. starting at the original GoSyscall).
//
// The resulting trace treats the old trace as a single, large generation,
// sharing a single evTable for all events.
//
// We use a new (compared to what was used for 'go tool trace' in earlier
// versions of Go) parser for old traces that is optimized for speed, low memory
// usage, and minimal GC pressure. It allocates events in batches so that even
// though we have to load the entire trace into memory, the conversion process
// shouldn't result in a doubling of memory usage, even if all converted events
// are kept alive, as we free batches once we're done with them.
//
// The conversion process is lossless.

package trace

import (
	"errors"
	"fmt"
	"internal/trace/v2/domtrace"
	"internal/trace/v2/event"
	"internal/trace/v2/event/go122"
)

type convertIter struct {
	trace          domtrace.Trace
	evt            *evTable
	preInit        bool
	createdPreInit map[GoID]struct{}
	bucket         int
	intraBucket    int
	events         domtrace.BucketSlice
	extra          []Event
	extraArr       [3]Event
	syscalls       map[GoID]*domtrace.Event
	tasks          map[TaskID]taskState

	inlineToStringID  []uint64
	builtinToStringID []uint64
}

const (
	// Block reasons
	sForever = iota
	sPreempted
	sGosched
	sSleep
	sChanSend
	sChanRecv
	sNetwork
	sSync
	sSyncCond
	sSelect
	sEmpty
	sMarkAssistWait

	// STW kinds
	sSTWUnknown
	sSTWGCMarkTermination
	sSTWGCSweepTermination
	sSTWWriteHeapDump
	sSTWGoroutineProfile
	sSTWGoroutineProfileCleanup
	sSTWAllGoroutinesStackTrace
	sSTWReadMemStats
	sSTWAllThreadsSyscall
	sSTWGOMAXPROCS
	sSTWStartTrace
	sSTWStopTrace
	sSTWCountPagesInUse
	sSTWReadMetricsSlow
	sSTWReadMemStatsSlow
	sSTWPageCachePagesLeaked
	sSTWResetDebugLog

	sLast
)

func (it *convertIter) init(pr domtrace.Trace) error {
	it.trace = pr
	it.preInit = true
	it.createdPreInit = make(map[GoID]struct{})
	it.evt = &evTable{pcs: make(map[uint64]frame)}
	it.events = pr.Events
	it.syscalls = make(map[GoID]*domtrace.Event)
	it.extra = it.extraArr[:0]

	evt := it.evt

	// Convert from domtracer's Strings map to our dataTable.
	var max uint64
	for id, s := range pr.Strings {
		evt.strings.insert(stringID(id), s)
		if id > max {
			max = id
		}
	}
	pr.Strings = nil

	// Add all strings used for UserLog. In the old trace format, these were
	// stored inline and didn't have IDs. We generate IDs for them.
	if max+uint64(len(pr.InlineStrings)) < max {
		return errors.New("trace contains too many strings")
	}
	var addErr error
	add := func(id stringID, s string) {
		if err := evt.strings.insert(id, s); err != nil && addErr == nil {
			addErr = err
		}
	}
	for id, s := range pr.InlineStrings {
		nid := max + 1 + uint64(id)
		it.inlineToStringID = append(it.inlineToStringID, nid)
		add(stringID(nid), s)
	}
	max += uint64(len(pr.InlineStrings))
	pr.InlineStrings = nil

	// Add strings that the converter emits explicitly.
	if max+uint64(sLast) < max {
		return errors.New("trace contains too many strings")
	}
	it.builtinToStringID = make([]uint64, sLast)
	addBuiltin := func(c int, s string) {
		nid := max + 1 + uint64(c)
		it.builtinToStringID[c] = nid
		add(stringID(nid), s)
	}
	addBuiltin(sForever, "forever")
	addBuiltin(sPreempted, "preempted")
	addBuiltin(sGosched, "runtime.Gosched")
	addBuiltin(sSleep, "sleep")
	addBuiltin(sChanSend, "chan send")
	addBuiltin(sChanRecv, "chan receive")
	addBuiltin(sNetwork, "network")
	addBuiltin(sSync, "sync")
	addBuiltin(sSyncCond, "sync.(*Cond).Wait")
	addBuiltin(sSelect, "select")
	addBuiltin(sEmpty, "")
	addBuiltin(sMarkAssistWait, "GC mark assist wait for work")
	addBuiltin(sSTWUnknown, "")
	addBuiltin(sSTWGCMarkTermination, "GC mark termination")
	addBuiltin(sSTWGCSweepTermination, "GC sweep termination")
	addBuiltin(sSTWWriteHeapDump, "write heap dump")
	addBuiltin(sSTWGoroutineProfile, "goroutine profile")
	addBuiltin(sSTWGoroutineProfileCleanup, "goroutine profile cleanup")
	addBuiltin(sSTWAllGoroutinesStackTrace, "all goroutine stack trace")
	addBuiltin(sSTWReadMemStats, "read mem stats")
	addBuiltin(sSTWAllThreadsSyscall, "AllThreadsSyscall")
	addBuiltin(sSTWGOMAXPROCS, "GOMAXPROCS")
	addBuiltin(sSTWStartTrace, "start trace")
	addBuiltin(sSTWStopTrace, "stop trace")
	addBuiltin(sSTWCountPagesInUse, "CountPagesInUse (test)")
	addBuiltin(sSTWReadMetricsSlow, "ReadMetricsSlow (test)")
	addBuiltin(sSTWReadMemStatsSlow, "ReadMemStatsSlow (test)")
	addBuiltin(sSTWPageCachePagesLeaked, "PageCachePagesLeaked (test)")
	addBuiltin(sSTWResetDebugLog, "ResetDebugLog (test)")

	if addErr != nil {
		// This should be impossible but let's be safe.
		return fmt.Errorf("couldn't add strings: %w", addErr)
	}

	it.evt.strings.compactify()

	// Convert stacks.
	for id, stk := range pr.Stacks {
		evt.stacks.insert(stackID(id), stack{pcs: stk})
	}

	// OPT(dh): if we could share the frame type between this package and
	// domtrace we wouldn't have to copy the map.
	for pc, f := range pr.PCs {
		evt.pcs[pc] = frame{
			pc:     pc,
			funcID: stringID(f.Fn),
			fileID: stringID(f.File),
			line:   uint64(f.Line),
		}
	}
	pr.Stacks = nil
	pr.PCs = nil
	evt.stacks.compactify()
	return nil
}

// next returns the next event, or false if there are no more events.
func (it *convertIter) next() (Event, bool) {
	if len(it.extra) > 0 {
		ev := it.extra[0]
		it.extra = it.extra[1:]

		if len(it.extra) == 0 {
			it.extra = it.extraArr[:0]
		}
		return ev, true
	}

	if it.bucket == len(it.events.Buckets) {
		return Event{}, false
	}

	ev, ok := it.convertEvent(&it.events.Buckets[it.bucket][it.intraBucket])

	it.intraBucket++
	if it.intraBucket == domtrace.BucketSize || (it.bucket*domtrace.BucketSize+it.intraBucket) >= it.events.Len() {
		// Release memory of the bucket of events we just finished converting.
		it.events.Buckets[it.bucket] = nil
		it.bucket++
		it.intraBucket = 0
	}

	if !ok {
		return it.next()
	}

	return ev, true
}

// convertEvent converts an event from the old trace format to zero or more
// events in the new format. Most events translate 1 to 1. Some events don't
// result in an event right away, in which case convertEvent returns false. Some
// events result in more than one new event; in this case, convertEvent returns
// the first event and stores additional events in it.extra.
func (it *convertIter) convertEvent(ev *domtrace.Event) (Event, bool) {
	var mappedType event.Type
	mappedArgs := ev.Args

	if ev.Type != domtrace.EvGoSysBlock {
		if syscall, ok := it.syscalls[GoID(ev.G)]; ok {
			// We held a syscall, but the next event on the G wasn't a
			// EvGoSysBlock. Emit the syscall, then put the conversion of this
			// event into it.extra.
			delete(it.syscalls, GoID(ev.G))

			// Convert the old instantaneous syscall event to a pair of syscall
			// begin and syscall end and give it the shortest possible duration,
			// 1ns.
			out1 := Event{
				ctx: schedCtx{
					G: GoID(syscall.G),
					P: ProcID(syscall.P),
					M: ThreadID(syscall.P),
				},
				table: it.evt,
				base: baseEvent{
					typ:  go122.EvGoSyscallBegin,
					time: Time(syscall.Ts),
					args: [4]uint64{1: uint64(syscall.StkID)},
				},
			}

			out2 := Event{
				ctx:   out1.ctx,
				table: it.evt,
				base: baseEvent{
					typ:  go122.EvGoSyscallEnd,
					time: Time(syscall.Ts + 1),
					args: [4]uint64{},
				},
			}

			it.extra = append(it.extra, out2)

			if next, ok := it.convertEvent(ev); ok {
				it.extra = append(it.extra, next)
			}

			return out1, true
		}
	}

	switch ev.Type {
	case domtrace.EvGomaxprocs:
		mappedType = go122.EvProcsChange
		if it.preInit {
			// The first EvGomaxprocs signals the end of trace initialization. At this point we've seen
			// all goroutines that already existed at trace begin.
			it.preInit = false
			for gid := range it.createdPreInit {
				// These are goroutines that already existed when tracing started but for which we
				// received neither GoWaiting, GoInSyscall, or GoStart. These are goroutines that are in
				// the states _Gidle or _Grunnable.
				it.extra = append(it.extra, Event{
					ctx: schedCtx{
						G: GoID(gid),
						P: NoProc,
						M: NoThread,
					},
					table: it.evt,
					base: baseEvent{
						typ:  go122.EvGoStatus,
						time: Time(ev.Ts),
						args: [4]uint64{uint64(gid), ^uint64(0), uint64(go122.GoRunnable)},
					},
				})
			}
			it.createdPreInit = nil
			return Event{}, false
		}
	case domtrace.EvProcStart:
		mappedType = go122.EvProcStart
		mappedArgs = [4]uint64{uint64(ev.P)}
	case domtrace.EvProcStop:
		mappedType = go122.EvProcStop
	case domtrace.EvGCStart:
		mappedType = go122.EvGCBegin
	case domtrace.EvGCDone:
		mappedType = go122.EvGCEnd
	case domtrace.EvSTWStart:
		sid := it.builtinToStringID[sSTWUnknown+it.trace.STWReason(ev.Args[0])]
		mappedType = go122.EvSTWBegin
		mappedArgs = [4]uint64{uint64(sid)}
	case domtrace.EvSTWDone:
		mappedType = go122.EvSTWEnd
	case domtrace.EvGCSweepStart:
		mappedType = go122.EvGCSweepBegin
	case domtrace.EvGCSweepDone:
		mappedType = go122.EvGCSweepEnd
	case domtrace.EvGoCreate:
		if it.preInit {
			it.createdPreInit[GoID(ev.Args[0])] = struct{}{}
			return Event{}, false
		}
		mappedType = go122.EvGoCreate
	case domtrace.EvGoStart:
		if it.preInit {
			mappedType = go122.EvGoStatus
			mappedArgs = [4]uint64{ev.Args[0], ^uint64(0), uint64(go122.GoRunning)}
			delete(it.createdPreInit, GoID(ev.Args[0]))
		} else {
			mappedType = go122.EvGoStart
		}
	case domtrace.EvGoStartLabel:
		it.extra = []Event{{
			ctx: schedCtx{
				G: GoID(ev.G),
				P: ProcID(ev.P),
				M: ThreadID(ev.P),
			},
			table: it.evt,
			base: baseEvent{
				typ:  go122.EvGoLabel,
				time: Time(ev.Ts),
				args: [4]uint64{ev.Args[2]},
			},
		}}
		return Event{
			ctx: schedCtx{
				G: GoID(ev.G),
				P: ProcID(ev.P),
				M: ThreadID(ev.P),
			},
			table: it.evt,
			base: baseEvent{
				typ:  go122.EvGoStart,
				time: Time(ev.Ts),
				args: ev.Args,
			},
		}, true
	case domtrace.EvGoEnd:
		mappedType = go122.EvGoDestroy
	case domtrace.EvGoStop:
		mappedType = go122.EvGoBlock
		mappedArgs = [4]uint64{uint64(it.builtinToStringID[sForever]), uint64(ev.StkID)}
	case domtrace.EvGoSched:
		mappedType = go122.EvGoStop
		mappedArgs = [4]uint64{uint64(it.builtinToStringID[sGosched]), uint64(ev.StkID)}
	case domtrace.EvGoPreempt:
		mappedType = go122.EvGoStop
		mappedArgs = [4]uint64{uint64(it.builtinToStringID[sPreempted]), uint64(ev.StkID)}
	case domtrace.EvGoSleep:
		mappedType = go122.EvGoStop
		mappedArgs = [4]uint64{uint64(it.builtinToStringID[sSleep]), uint64(ev.StkID)}
	case domtrace.EvGoBlock:
		mappedType = go122.EvGoBlock
		mappedArgs = [4]uint64{uint64(it.builtinToStringID[sEmpty]), uint64(ev.StkID)}
	case domtrace.EvGoUnblock:
		mappedType = go122.EvGoUnblock
	case domtrace.EvGoBlockSend:
		mappedType = go122.EvGoBlock
		mappedArgs = [4]uint64{uint64(it.builtinToStringID[sChanSend]), uint64(ev.StkID)}
	case domtrace.EvGoBlockRecv:
		mappedType = go122.EvGoBlock
		mappedArgs = [4]uint64{uint64(it.builtinToStringID[sChanRecv]), uint64(ev.StkID)}
	case domtrace.EvGoBlockSelect:
		mappedType = go122.EvGoBlock
		mappedArgs = [4]uint64{uint64(it.builtinToStringID[sSelect]), uint64(ev.StkID)}
	case domtrace.EvGoBlockSync:
		mappedType = go122.EvGoBlock
		mappedArgs = [4]uint64{uint64(it.builtinToStringID[sSync]), uint64(ev.StkID)}
	case domtrace.EvGoBlockCond:
		mappedType = go122.EvGoBlock
		mappedArgs = [4]uint64{uint64(it.builtinToStringID[sSyncCond]), uint64(ev.StkID)}
	case domtrace.EvGoBlockNet:
		mappedType = go122.EvGoBlock
		mappedArgs = [4]uint64{uint64(it.builtinToStringID[sNetwork]), uint64(ev.StkID)}
	case domtrace.EvGoBlockGC:
		mappedType = go122.EvGoBlock
		mappedArgs = [4]uint64{uint64(it.builtinToStringID[sMarkAssistWait]), uint64(ev.StkID)}
	case domtrace.EvGoSysCall:
		it.syscalls[GoID(ev.G)] = ev
		return Event{}, false
	case domtrace.EvGoSysExit:
		mappedType = go122.EvGoSyscallEndBlocked
	case domtrace.EvGoSysBlock:
		syscall := it.syscalls[GoID(ev.G)]
		delete(it.syscalls, GoID(ev.G))
		mappedType = go122.EvGoSyscallBegin
		ev = syscall
		mappedArgs = [4]uint64{1: uint64(ev.StkID)}
	case domtrace.EvGoWaiting:
		mappedType = go122.EvGoStatus
		mappedArgs = [4]uint64{ev.Args[0], ^uint64(0), uint64(go122.GoWaiting)}
		delete(it.createdPreInit, GoID(ev.Args[0]))
	case domtrace.EvGoInSyscall:
		mappedType = go122.EvGoStatus
		mappedArgs = [4]uint64{ev.Args[0], ^uint64(0), uint64(go122.GoSyscall)}
		delete(it.createdPreInit, GoID(ev.Args[0]))
	case domtrace.EvHeapAlloc:
		mappedType = go122.EvHeapAlloc
	case domtrace.EvHeapGoal:
		mappedType = go122.EvHeapGoal
	case domtrace.EvGCMarkAssistStart:
		mappedType = go122.EvGCMarkAssistBegin
	case domtrace.EvGCMarkAssistDone:
		mappedType = go122.EvGCMarkAssistEnd
	case domtrace.EvUserTaskCreate:
		mappedType = go122.EvUserTaskBegin
		mappedArgs = [4]uint64{ev.Args[0], ev.Args[1], ev.Args[3], uint64(ev.StkID)}
		name, _ := it.evt.strings.get(stringID(ev.Args[3]))
		it.tasks[TaskID(ev.Args[0])] = taskState{name: name, parentID: TaskID(ev.Args[1])}
	case domtrace.EvUserTaskEnd:
		mappedType = go122.EvUserTaskEnd
		// Event.Task expects the parent and name to be smuggled in extra args
		// and as extra strings.
		ts, ok := it.tasks[TaskID(ev.Args[0])]
		if ok {
			delete(it.tasks, TaskID(ev.Args[0]))
			mappedArgs = [4]uint64{
				ev.Args[0],
				ev.Args[1],
				uint64(ts.parentID),
				uint64(it.evt.addExtraString(ts.name)),
			}
		} else {
			mappedArgs = [4]uint64{ev.Args[0], ev.Args[1], uint64(NoTask), uint64(it.evt.addExtraString(""))}
		}
	case domtrace.EvUserRegion:
		switch ev.Args[1] {
		case 0: // start
			mappedType = go122.EvUserRegionBegin
		case 1: // end
			mappedType = go122.EvUserRegionEnd
		}
		mappedArgs = [4]uint64{ev.Args[0], ev.Args[2], uint64(ev.StkID)}
	case domtrace.EvUserLog:
		mappedType = go122.EvUserLog
		mappedArgs = [4]uint64{ev.Args[0], ev.Args[1], it.inlineToStringID[ev.Args[3]], uint64(ev.StkID)}
	case domtrace.EvCPUSample:
		mappedType = go122.EvCPUSample
		mappedArgs = [4]uint64{0, ev.Args[2], ev.Args[3], uint64(ev.StkID)}
	default:
		panic(ev.Type)
	}

	if domtrace.EventDescriptions[ev.Type].Stack {
		if stackIDs := go122.Specs()[mappedType].StackIDs; len(stackIDs) > 0 {
			mappedArgs[stackIDs[0]-1] = uint64(ev.StkID)
		}
	}

	return Event{
		ctx: schedCtx{
			G: GoID(ev.G),
			P: ProcID(ev.P),
			// the validator expects valid Ms. Pretending that every P has its
			// own M should be safe.
			M: ThreadID(ev.P),
		},
		table: it.evt,
		base: baseEvent{
			typ:  mappedType,
			time: Time(ev.Ts),
			args: mappedArgs,
		},
	}, true
}

// convertOldFormat takes a fully loaded trace in the old trace format and
// returns an iterator over events in the new format.
func convertOldFormat(pr domtrace.Trace) *convertIter {
	it := &convertIter{}
	it.init(pr)
	return it
}
