package trace

import (
	"errors"
	"fmt"
	"internal/trace/v2/domtrace"
	"internal/trace/v2/event"
	"internal/trace/v2/event/go122"
)

// XXX figure out what's meant to go into base.extra
// apparently extraStrings for user tasks because tasks can span generations

type oldEventsIter struct {
	trace          domtrace.Trace
	evt            *evTable
	preInit        bool
	createdPreInit map[GoID]struct{}
	bucket         int
	intraBucket    int
	events         domtrace.BucketSlice
	extra          []Event
	syscalls       map[GoID]*domtrace.Event

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

func (it *oldEventsIter) init(pr domtrace.Trace) error {
	it.trace = pr
	it.preInit = true
	it.createdPreInit = make(map[GoID]struct{})
	it.evt = &evTable{}
	it.events = pr.Events
	it.syscalls = make(map[GoID]*domtrace.Event)

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
		evt.strings.insert(stringID(nid), s)
	}
	max += uint64(len(pr.InlineStrings))

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
	// XXX make sure these strings match 1.22
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
	// XXX what about "system goroutine wait", "GC background sweeper wait", "wait for debug call", "wait
	// until GC ends"

	if addErr != nil {
		// This should be impossible but let's be safe.
		return fmt.Errorf("couldn't add strings: %w", addErr)
	}

	it.evt.strings.compactify()

	// Convert stacks.
	for id, stk := range pr.Stacks {
		stkv2 := stack{
			frames: make([]frame, len(stk)),
		}
		for i, pc := range stk {
			framev1 := pr.PCs[pc]
			framev2 := frame{
				pc:     pc,
				funcID: stringID(framev1.Fn),
				fileID: stringID(framev1.File),
				line:   uint64(framev1.Line),
			}
			stkv2.frames[i] = framev2
		}
		evt.stacks.insert(stackID(id), stkv2)
	}
	pr.Stacks = nil
	evt.stacks.compactify()
	return nil
}

// next returns the next event, or false if there are no more events.
func (it *oldEventsIter) next() (Event, bool) {
	if len(it.extra) > 0 {
		ev := it.extra[0]
		it.extra = it.extra[1:]

		if len(it.extra) == 0 {
			// After trace initialization, we will have one extra item per existing goroutine. After that,
			// we'll only ever have one extra item. Don't keep around too much memory, but don't allocate
			// every time we have to store one extra item.
			if cap(it.extra) > 1 {
				it.extra = nil
			} else {
				it.extra = it.extra[:0]
			}
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
func (it *oldEventsIter) convertEvent(ev *domtrace.Event) (Event, bool) {
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
					M: NoThread,
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
				M: NoThread,
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
				M: NoThread,
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
		syscall, ok := it.syscalls[GoID(ev.G)]
		if !ok {
			// XXX report failure
		}
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
		//XXX think about extraStrings and args
		mappedType = go122.EvUserTaskBegin
		mappedArgs = [4]uint64{ev.Args[0], ev.Args[1], ev.Args[3], uint64(ev.StkID)}
	case domtrace.EvUserTaskEnd:
		mappedType = go122.EvUserTaskEnd
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
			M: NoThread,
		},
		table: it.evt,
		base: baseEvent{
			typ:  mappedType,
			time: Time(ev.Ts),
			args: mappedArgs,
		},
	}, true
}

func ConvertOld(pr domtrace.Trace) *oldEventsIter {
	it := &oldEventsIter{}
	it.init(pr)
	return it
}
