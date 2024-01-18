package trace

import (
	"internal/trace/v2/domtrace"
	"internal/trace/v2/event"
	"internal/trace/v2/event/go122"
)

func ConvertOld(pr domtrace.Trace) []Event {
	// TODO populate evt.frequency

	evt := evTable{}

	for id, s := range pr.Strings {
		evt.strings.insert(stringID(id), s)
	}
	evt.strings.compactify()

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
	evt.stacks.compactify()

	eventsv2 := make([]Event, len(pr.Events))
	for i, ev := range pr.Events {
		var mappedType event.Type
		switch ev.Type {
		case domtrace.EvGomaxprocs:
			mappedType = go122.EvProcsChange
		case domtrace.EvProcStart:
			mappedType = go122.EvProcStart
		case domtrace.EvProcStop:
			mappedType = go122.EvProcStop
		case domtrace.EvGCStart:
			mappedType = go122.EvGCBegin
		case domtrace.EvGCDone:
			mappedType = go122.EvGCEnd
		case domtrace.EvSTWStart:
			mappedType = go122.EvSTWBegin
		case domtrace.EvSTWDone:
			mappedType = go122.EvSTWEnd
		case domtrace.EvGCSweepStart:
			mappedType = go122.EvGCSweepBegin
		case domtrace.EvGCSweepDone:
			mappedType = go122.EvGCSweepEnd
		case domtrace.EvGoCreate:
			mappedType = go122.EvGoCreate
		case domtrace.EvGoStart:
			mappedType = go122.EvGoStart
		case domtrace.EvGoEnd:
			mappedType = go122.EvGoDestroy
		case domtrace.EvGoStop:
		case domtrace.EvGoSched:
		case domtrace.EvGoPreempt:
		case domtrace.EvGoSleep:
		case domtrace.EvGoBlock:
			mappedType = go122.EvGoBlock
		case domtrace.EvGoUnblock:
			mappedType = go122.EvGoUnblock
		case domtrace.EvGoBlockSend:
			mappedType = go122.EvGoBlock
		case domtrace.EvGoBlockRecv:
			mappedType = go122.EvGoBlock
		case domtrace.EvGoBlockSelect:
			mappedType = go122.EvGoBlock
		case domtrace.EvGoBlockSync:
			mappedType = go122.EvGoBlock
		case domtrace.EvGoBlockCond:
			mappedType = go122.EvGoBlock
		case domtrace.EvGoBlockNet:
			mappedType = go122.EvGoBlock
		case domtrace.EvGoBlockGC:
			mappedType = go122.EvGoBlock
		case domtrace.EvGoSysCall:
			// TODO handle this
		case domtrace.EvGoSysExit:
			mappedType = go122.EvGoSyscallEndBlocked
		case domtrace.EvGoSysBlock:
			mappedType = go122.EvGoSyscallBegin
		case domtrace.EvGoWaiting:
		case domtrace.EvGoInSyscall:
			// XXX EvGoStatus
		case domtrace.EvHeapAlloc:
			mappedType = go122.EvHeapAlloc
		case domtrace.EvHeapGoal:
			mappedType = go122.EvHeapGoal
		case domtrace.EvGoStartLabel:
			// XXX start + label
		case domtrace.EvGCMarkAssistStart:
			mappedType = go122.EvGCMarkAssistBegin
		case domtrace.EvGCMarkAssistDone:
			mappedType = go122.EvGCMarkAssistEnd
		case domtrace.EvUserTaskCreate:
			mappedType = go122.EvUserTaskBegin
		case domtrace.EvUserTaskEnd:
			mappedType = go122.EvUserTaskEnd
		case domtrace.EvUserRegion:
			// Depending on the mode:
			mappedType = go122.EvUserRegionBegin
			mappedType = go122.EvUserRegionEnd
		case domtrace.EvUserLog:
			mappedType = go122.EvUserLog
		case domtrace.EvCPUSample:
			mappedType = go122.EvCPUSample
		}

		be := baseEvent{
			typ:  mappedType,
			time: Time(ev.Ts),
			args: ev.Args,
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
		eventsv2[i] = evv2
	}

	return eventsv2
}
