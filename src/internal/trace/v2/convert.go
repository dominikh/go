package trace

import (
	"internal/trace/v2/domtrace"
	"internal/trace/v2/event"
	"internal/trace/v2/event/go122"
	"math"
	"os"
	"runtime/pprof"
)

// XXX figure out what's meant to go into base.extra
// apparently extraStrings for user tasks because tasks can span generations

func ConvertOld(pr domtrace.Trace) <-chan Event {
	// TODO populate evt.frequency

	evt := evTable{}

	for id, s := range pr.Strings {
		evt.strings.insert(stringID(id), s)
	}
	pr.Strings = nil
	evt.strings.compactify()
	const (
		// Block reasons
		sForever stringID = math.MaxUint64 - iota
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
	)
	evt.strings.insert(sForever, "forever")
	evt.strings.insert(sPreempted, "preempted")
	evt.strings.insert(sGosched, "runtime.Gosched")
	evt.strings.insert(sSleep, "sleep")
	evt.strings.insert(sChanSend, "chan send")
	evt.strings.insert(sChanRecv, "chan receive")
	evt.strings.insert(sNetwork, "network")
	evt.strings.insert(sSync, "sync")
	evt.strings.insert(sSyncCond, "sync.(*Cond).Wait")
	evt.strings.insert(sSelect, "select")
	evt.strings.insert(sEmpty, "")
	evt.strings.insert(sMarkAssistWait, "GC mark assist wait for work")

	// XXX make sure these strings match 1.22
	evt.strings.insert(sSTWUnknown, "")
	evt.strings.insert(sSTWGCMarkTermination, "GC mark termination")
	evt.strings.insert(sSTWGCSweepTermination, "GC sweep termination")
	evt.strings.insert(sSTWWriteHeapDump, "write heap dump")
	evt.strings.insert(sSTWGoroutineProfile, "goroutine profile")
	evt.strings.insert(sSTWGoroutineProfileCleanup, "goroutine profile cleanup")
	evt.strings.insert(sSTWAllGoroutinesStackTrace, "all goroutine stack trace")
	evt.strings.insert(sSTWReadMemStats, "read mem stats")
	evt.strings.insert(sSTWAllThreadsSyscall, "AllThreadsSyscall")
	evt.strings.insert(sSTWGOMAXPROCS, "GOMAXPROCS")
	evt.strings.insert(sSTWStartTrace, "start trace")
	evt.strings.insert(sSTWStopTrace, "stop trace")
	evt.strings.insert(sSTWCountPagesInUse, "CountPagesInUse (test)")
	evt.strings.insert(sSTWReadMetricsSlow, "ReadMetricsSlow (test)")
	evt.strings.insert(sSTWReadMemStatsSlow, "ReadMemStatsSlow (test)")
	evt.strings.insert(sSTWPageCachePagesLeaked, "PageCachePagesLeaked (test)")
	evt.strings.insert(sSTWResetDebugLog, "ResetDebugLog (test)")

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

	out := make(chan Event, 1024)
	go func() {
		preInit := true
		createdPreInit := make(map[GoID]struct{})
		for i, bucket := range pr.Events.Buckets {
			for j := range bucket {
				if i*len(bucket)+j >= pr.Events.Len() {
					break
				}
				ev := &bucket[j]
				var mappedType event.Type
				mappedArgs := ev.Args
				switch ev.Type {
				case domtrace.EvGomaxprocs:
					mappedType = go122.EvProcsChange
					if preInit {
						// The first EvGomaxprocs signals the end of trace initialization. At this point we've seen
						// all goroutines that already existed at trace begin.
						preInit = false
						for gid := range createdPreInit {
							// These are goroutines that already existed when tracing started but for which we
							// received neither GoWaiting, GoInSyscall, or GoStart. These are goroutines that are in
							// the states _Gidle or _Grunnable.
							out <- Event{
								ctx: schedCtx{
									G: GoID(gid),
									P: NoProc,
									M: NoThread,
								},
								table: &evt,
								base: baseEvent{
									typ:  go122.EvGoStatus,
									time: Time(ev.Ts),
									args: [4]uint64{uint64(gid), ^uint64(0), uint64(go122.GoRunnable)},
								},
							}
						}
						createdPreInit = nil
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
					sid := sSTWUnknown - stringID(pr.STWReason(ev.Args[0]))
					mappedType = go122.EvSTWBegin
					mappedArgs = [4]uint64{uint64(sid)}
				case domtrace.EvSTWDone:
					mappedType = go122.EvSTWEnd
				case domtrace.EvGCSweepStart:
					mappedType = go122.EvGCSweepBegin
				case domtrace.EvGCSweepDone:
					mappedType = go122.EvGCSweepEnd
				case domtrace.EvGoCreate:
					if preInit {
						createdPreInit[GoID(ev.Args[0])] = struct{}{}
						continue
					}
					mappedType = go122.EvGoCreate
				case domtrace.EvGoStart:
					if preInit {
						mappedType = go122.EvGoStatus
						mappedArgs = [4]uint64{ev.Args[0], ^uint64(0), uint64(go122.GoRunning)}
						delete(createdPreInit, GoID(ev.Args[0]))
					} else {
						mappedType = go122.EvGoStart
					}
				case domtrace.EvGoStartLabel:
					out <- Event{
						ctx: schedCtx{
							G: GoID(ev.G),
							P: ProcID(ev.P),
							M: NoThread,
						},
						table: &evt,
						base: baseEvent{
							typ:  go122.EvGoStart,
							time: Time(ev.Ts),
							args: ev.Args,
						},
					}
					out <- Event{
						ctx: schedCtx{
							G: GoID(ev.G),
							P: ProcID(ev.P),
							M: NoThread,
						},
						table: &evt,
						base: baseEvent{
							typ:  go122.EvGoLabel,
							time: Time(ev.Ts),
							args: [4]uint64{ev.Args[2]},
						},
					}
					continue
				case domtrace.EvGoEnd:
					mappedType = go122.EvGoDestroy
				case domtrace.EvGoStop:
					mappedType = go122.EvGoBlock
					mappedArgs = [4]uint64{uint64(sForever), ev.Args[0]}
				case domtrace.EvGoSched:
					mappedType = go122.EvGoStop
					mappedArgs = [4]uint64{uint64(sGosched), ev.Args[0]}
				case domtrace.EvGoPreempt:
					mappedType = go122.EvGoStop
					mappedArgs = [4]uint64{uint64(sPreempted), ev.Args[0]}
				case domtrace.EvGoSleep:
					mappedType = go122.EvGoStop
					mappedArgs = [4]uint64{uint64(sSleep), ev.Args[0]}
				case domtrace.EvGoBlock:
					mappedType = go122.EvGoBlock
					mappedArgs = [4]uint64{uint64(sEmpty), ev.Args[0]}
				case domtrace.EvGoUnblock:
					mappedType = go122.EvGoUnblock
				case domtrace.EvGoBlockSend:
					mappedType = go122.EvGoBlock
					mappedArgs = [4]uint64{uint64(sChanSend), ev.Args[0]}
				case domtrace.EvGoBlockRecv:
					mappedType = go122.EvGoBlock
					mappedArgs = [4]uint64{uint64(sChanRecv), ev.Args[0]}
				case domtrace.EvGoBlockSelect:
					mappedType = go122.EvGoBlock
					mappedArgs = [4]uint64{uint64(sSelect), ev.Args[0]}
				case domtrace.EvGoBlockSync:
					mappedType = go122.EvGoBlock
					mappedArgs = [4]uint64{uint64(sSync), ev.Args[0]}
				case domtrace.EvGoBlockCond:
					mappedType = go122.EvGoBlock
					mappedArgs = [4]uint64{uint64(sSyncCond), ev.Args[0]}
				case domtrace.EvGoBlockNet:
					mappedType = go122.EvGoBlock
					mappedArgs = [4]uint64{uint64(sNetwork), ev.Args[0]}
				case domtrace.EvGoBlockGC:
					mappedType = go122.EvGoBlock
					mappedArgs = [4]uint64{uint64(sMarkAssistWait), ev.Args[0]}
				case domtrace.EvGoSysCall:
					// TODO handle this

					// If the next event on the same G is EvGoSysBlock, then this event is the start of a syscall and EvGoSysExit is the end.

					// I have no idea how to represent non-blocking syscalls, as previously these were just
					// instantaneous events. maybe make them 1 ns long syscall?

				case domtrace.EvGoSysExit:
					mappedType = go122.EvGoSyscallEndBlocked
				case domtrace.EvGoSysBlock:
					//XXX we need the args vom EvGoSysCall
					mappedType = go122.EvGoSyscallBegin
				case domtrace.EvGoWaiting:
					mappedType = go122.EvGoStatus
					mappedArgs = [4]uint64{ev.Args[0], ^uint64(0), uint64(go122.GoWaiting)}
					delete(createdPreInit, GoID(ev.Args[0]))
				case domtrace.EvGoInSyscall:
					mappedType = go122.EvGoStatus
					mappedArgs = [4]uint64{ev.Args[0], ^uint64(0), uint64(go122.GoSyscall)}
					delete(createdPreInit, GoID(ev.Args[0]))
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
					// Depending on the mode:
					// XXX implement
					mappedType = go122.EvUserRegionBegin
					mappedType = go122.EvUserRegionEnd
				case domtrace.EvUserLog:
					mappedType = go122.EvUserLog
				case domtrace.EvCPUSample:
					mappedType = go122.EvCPUSample
					mappedArgs = [4]uint64{0, ev.Args[2], ev.Args[3], ev.Args[0]}
				default:
					panic(ev.Type)
				}

				be := baseEvent{
					typ:  mappedType,
					time: Time(ev.Ts),
					args: mappedArgs,
				}
				evv2 := Event{
					ctx: schedCtx{
						G: GoID(ev.G),
						P: ProcID(ev.P),
						M: NoThread,
					},
					table: &evt,
					base:  be,
				}
				if mappedType != 0 {
					out <- evv2
				}
			}
			// Release memory once we're done with a bucket
			pr.Events.Buckets[i] = nil
		}
		close(out)
		pprof.WriteHeapProfile(os.Stdout)
	}()
	return out
}
