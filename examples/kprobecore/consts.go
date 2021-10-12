package main

// State is lifted from the kernel: uapi/linux/neighbour.h
type State uint8

const (
	NUD_INCOMPLETE State = 0x01
	NUD_REACHABLE  State = 0x02
	NUD_STALE      State = 0x04
	NUD_DELAY      State = 0x08
	NUD_PROBE      State = 0x10
	NUD_FAILED     State = 0x20

	/* Dummy states */
	NUD_NOARP     State = 0x40
	NUD_PERMANENT State = 0x80
	NUD_NONE      State = 0x00
)

func (s State) String() string {
	switch s {
	case NUD_INCOMPLETE:
		return "NUD_INCOMPLETE"
	case NUD_REACHABLE:
		return "NUD_REACHABLE"
	case NUD_STALE:
		return "NUD_STALE"
	case NUD_DELAY:
		return "NUD_DELAY"
	case NUD_PROBE:
		return "NUD_PROBE"
	case NUD_FAILED:
		return "NUD_FAILED"
	case NUD_NOARP:
		return "NUD_NOARP"
	case NUD_PERMANENT:
		return "NUD_PERMANENT"
	case NUD_NONE:
		return "NUD_NONE"
	default:
		return ""
	}
}
