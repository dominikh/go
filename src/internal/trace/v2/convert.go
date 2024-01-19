package trace

import (
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

	extraStrings [sLast]stringID
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

func (it *oldEventsIter) builtinString(id uint64) stringID {
	return stringID(it.trace.SmallestExtraString - 1 - id)
}

func (it *oldEventsIter) init(pr domtrace.Trace) {
	it.trace = pr
	it.preInit = true
	it.createdPreInit = make(map[GoID]struct{})
	it.evt = &evTable{}
	it.events = pr.Events

	evt := it.evt

	for id, s := range pr.Strings {
		evt.strings.insert(stringID(id), s)
	}
	pr.Strings = nil
	it.evt.strings.compactify()
	evt.strings.insert(it.builtinString(sForever), "forever")
	evt.strings.insert(it.builtinString(sPreempted), "preempted")
	evt.strings.insert(it.builtinString(sGosched), "runtime.Gosched")
	evt.strings.insert(it.builtinString(sSleep), "sleep")
	evt.strings.insert(it.builtinString(sChanSend), "chan send")
	evt.strings.insert(it.builtinString(sChanRecv), "chan receive")
	evt.strings.insert(it.builtinString(sNetwork), "network")
	evt.strings.insert(it.builtinString(sSync), "sync")
	evt.strings.insert(it.builtinString(sSyncCond), "sync.(*Cond).Wait")
	evt.strings.insert(it.builtinString(sSelect), "select")
	evt.strings.insert(it.builtinString(sEmpty), "")
	evt.strings.insert(it.builtinString(sMarkAssistWait), "GC mark assist wait for work")

	// XXX make sure these strings match 1.22
	evt.strings.insert(it.builtinString(sSTWUnknown), "")
	evt.strings.insert(it.builtinString(sSTWGCMarkTermination), "GC mark termination")
	evt.strings.insert(it.builtinString(sSTWGCSweepTermination), "GC sweep termination")
	evt.strings.insert(it.builtinString(sSTWWriteHeapDump), "write heap dump")
	evt.strings.insert(it.builtinString(sSTWGoroutineProfile), "goroutine profile")
	evt.strings.insert(it.builtinString(sSTWGoroutineProfileCleanup), "goroutine profile cleanup")
	evt.strings.insert(it.builtinString(sSTWAllGoroutinesStackTrace), "all goroutine stack trace")
	evt.strings.insert(it.builtinString(sSTWReadMemStats), "read mem stats")
	evt.strings.insert(it.builtinString(sSTWAllThreadsSyscall), "AllThreadsSyscall")
	evt.strings.insert(it.builtinString(sSTWGOMAXPROCS), "GOMAXPROCS")
	evt.strings.insert(it.builtinString(sSTWStartTrace), "start trace")
	evt.strings.insert(it.builtinString(sSTWStopTrace), "stop trace")
	evt.strings.insert(it.builtinString(sSTWCountPagesInUse), "CountPagesInUse (test)")
	evt.strings.insert(it.builtinString(sSTWReadMetricsSlow), "ReadMetricsSlow (test)")
	evt.strings.insert(it.builtinString(sSTWReadMemStatsSlow), "ReadMemStatsSlow (test)")
	evt.strings.insert(it.builtinString(sSTWPageCachePagesLeaked), "PageCachePagesLeaked (test)")
	evt.strings.insert(it.builtinString(sSTWResetDebugLog), "ResetDebugLog (test)")

	if s, ok := evt.strings.get(it.builtinString(sForever)); !ok || s != "forever" {
		panic(s)
	}

	// XXX what about "system goroutine wait", "GC background sweeper wait", "wait for debug call", "wait
	// until GC ends"

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
		// Release memory
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
		sid := it.builtinString(uint64(sSTWUnknown - it.trace.STWReason(ev.Args[0])))
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
		mappedArgs = [4]uint64{uint64(it.builtinString(sForever)), ev.Args[0]}
	case domtrace.EvGoSched:
		mappedType = go122.EvGoStop
		mappedArgs = [4]uint64{uint64(it.builtinString(sGosched)), ev.Args[0]}
	case domtrace.EvGoPreempt:
		mappedType = go122.EvGoStop
		mappedArgs = [4]uint64{uint64(it.builtinString(sPreempted)), ev.Args[0]}
	case domtrace.EvGoSleep:
		mappedType = go122.EvGoStop
		mappedArgs = [4]uint64{uint64(it.builtinString(sSleep)), ev.Args[0]}
	case domtrace.EvGoBlock:
		mappedType = go122.EvGoBlock
		mappedArgs = [4]uint64{uint64(it.builtinString(sEmpty)), ev.Args[0]}
	case domtrace.EvGoUnblock:
		mappedType = go122.EvGoUnblock
	case domtrace.EvGoBlockSend:
		mappedType = go122.EvGoBlock
		mappedArgs = [4]uint64{uint64(it.builtinString(sChanSend)), ev.Args[0]}
	case domtrace.EvGoBlockRecv:
		mappedType = go122.EvGoBlock
		mappedArgs = [4]uint64{uint64(it.builtinString(sChanRecv)), ev.Args[0]}
	case domtrace.EvGoBlockSelect:
		mappedType = go122.EvGoBlock
		mappedArgs = [4]uint64{uint64(it.builtinString(sSelect)), ev.Args[0]}
	case domtrace.EvGoBlockSync:
		mappedType = go122.EvGoBlock
		mappedArgs = [4]uint64{uint64(it.builtinString(sSync)), ev.Args[0]}
	case domtrace.EvGoBlockCond:
		mappedType = go122.EvGoBlock
		mappedArgs = [4]uint64{uint64(it.builtinString(sSyncCond)), ev.Args[0]}
	case domtrace.EvGoBlockNet:
		mappedType = go122.EvGoBlock
		mappedArgs = [4]uint64{uint64(it.builtinString(sNetwork)), ev.Args[0]}
	case domtrace.EvGoBlockGC:
		mappedType = go122.EvGoBlock
		mappedArgs = [4]uint64{uint64(it.builtinString(sMarkAssistWait)), ev.Args[0]}
	case domtrace.EvGoSysCall:
		// TODO handle this

		// If the next event on the same G is EvGoSysBlock, then this event is the start of a syscall and EvGoSysExit is the end.

		// I have no idea how to represent non-blocking syscalls, as previously these were just
		// instantaneous events. maybe make them 1 ns long syscall?
		return Event{}, false
	case domtrace.EvGoSysExit:
		mappedType = go122.EvGoSyscallEndBlocked
	case domtrace.EvGoSysBlock:
		//XXX we need the args vom EvGoSysCall
		mappedType = go122.EvGoSyscallBegin
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
		mappedArgs = [4]uint64{ev.Args[0], ev.Args[1], ev.Args[3], ev.Args[2]}
	case domtrace.EvUserTaskEnd:
		mappedType = go122.EvUserTaskEnd
	case domtrace.EvUserRegion:
		switch ev.Args[1] {
		case 0: // start
			mappedType = go122.EvUserRegionBegin
		case 1: // end
			mappedType = go122.EvUserRegionEnd
		}
		mappedArgs = [4]uint64{ev.Args[0], ev.Args[3], ev.Args[2]}
	case domtrace.EvUserLog:
		mappedType = go122.EvUserLog
		mappedArgs = [4]uint64{ev.Args[0], ev.Args[1], ev.Args[3], ev.Args[2]}
	case domtrace.EvCPUSample:
		mappedType = go122.EvCPUSample
		mappedArgs = [4]uint64{0, ev.Args[2], ev.Args[3], ev.Args[0]}
	default:
		panic(ev.Type)
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
