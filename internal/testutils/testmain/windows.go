package testmain

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
)

type tracelogKeywords uint64

// Know tracelog keywords.
//
// See https://github.com/microsoft/ebpf-for-windows/blob/main/libs/shared/ebpf_tracelog.h
var allKeywords = []string{
	"entry-exit",
	"base",
	"error",
	"epoch",
	"core",
	"link",
	"map",
	"program",
	"api",
	"printk",
	"native",
}

func (kw *tracelogKeywords) UnmarshalText(text []byte) error {
	decoded, err := strconv.ParseUint(string(text), 0, 64)
	if err != nil {
		return fmt.Errorf("foo: %w", err)
	}
	*kw = tracelogKeywords(decoded)
	return nil
}

func (kw tracelogKeywords) decode() []string {
	var keywords []string
	for _, keyword := range allKeywords {
		if kw&1 > 0 {
			keywords = append(keywords, keyword)
		}
		kw >>= 1
	}
	if kw > 0 {
		keywords = append(keywords, fmt.Sprintf("0x%x", kw))
	}
	return keywords
}

type tracelogLevel uint64

func (lvl tracelogLevel) String() string {
	// See https://learn.microsoft.com/en-us/windows/win32/api/traceloggingprovider/nf-traceloggingprovider-tracelogginglevel#remarks
	switch lvl {
	case 0:
		return ""
	case 1:
		return "C"
	case 2:
		return "E"
	case 3:
		return "W"
	case 4:
		return "I"
	case 5:
		return "V"
	default:
		return fmt.Sprintf("level(%d)", uint64(lvl))
	}
}

// startWPR starts a trace log for eBPF for Windows related events.
//
// * https://github.com/microsoft/ebpf-for-windows/blob/main/docs/GettingStarted.md#using-tracing
// * https://devblogs.microsoft.com/performance-diagnostics/controlling-the-event-session-name-with-the-instance-name/ and
func startWPR() (func(io.Writer) error, error) {
	if runtime.GOOS != "windows" {
		return func(io.Writer) error { return nil }, nil
	}

	def := filepath.Join(os.Getenv("ProgramFiles"), "ebpf-for-windows\\ebpfforwindows.wprp")
	if _, err := os.Stat(def); err != nil {
		return nil, err
	}

	path, err := os.MkdirTemp("", "ebpf-go-trace")
	if err != nil {
		return nil, err
	}

	session := fmt.Sprintf("epbf-go-%d", os.Getpid())
	wpr := exec.Command("wpr.exe", "-start", def, "-filemode", "-instancename", session)
	wpr.Stderr = os.Stderr
	if err := wpr.Run(); err != nil {
		_ = os.RemoveAll(path)
		return nil, err
	}

	return func(out io.Writer) error {
		defer os.RemoveAll(path)

		trace := filepath.Join(path, "trace.etl")
		wpr := exec.Command("wpr.exe", "-stop", trace, "-instancename", session)
		if err := wpr.Run(); err != nil {
			return err
		}

		if out == nil {
			return nil
		}

		netsh := exec.Command("netsh.exe", "trace", "convert", trace, "dump=XML")
		if err := netsh.Run(); err != nil {
			return err
		}

		f, err := os.Open(filepath.Join(path, "trace.xml"))
		if err != nil {
			return err
		}
		defer f.Close()

		return summariseWPRTrace(f, os.Stderr)
	}, nil
}

func summariseWPRTrace(r io.Reader, w io.Writer) error {
	type nameValue struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	}

	type event struct {
		XMLName xml.Name `xml:"Event"`
		System  struct {
			Provider struct {
				Name string `xml:"Name,attr"`
			} `xml:"Provider"`
			TimeCreated struct {
				SystemTime string `xml:"SystemTime,attr"`
			} `xml:"TimeCreated"`
			Keywords tracelogKeywords `xml:"Keywords"`
			Level    uint64           `xml:"Level"`
		} `xml:"System"`
		EventData struct {
			Data []nameValue `xml:"Data"`
		} `xml:"EventData"`
		RenderingInfo struct {
			Task string `xml:"Task"`
		} `xml:"RenderingInfo"`
	}

	var events struct {
		Events []event `xml:"Event"`
	}

	err := xml.NewDecoder(r).Decode(&events)
	if err != nil {
		return fmt.Errorf("unmarshal trace XML: %w", err)
	}

	tw := tabwriter.NewWriter(w, 0, 0, 1, ' ', 0)
	for _, event := range events.Events {
		if !strings.Contains(event.System.Provider.Name, "Ebpf") {
			continue
		}

		flag := " "
		// See https://learn.microsoft.com/en-us/windows/win32/api/traceloggingprovider/nf-traceloggingprovider-tracelogginglevel#remarks
		if event.System.Level > 0 && event.System.Level <= 3 {
			flag = "!"
		}

		kw := event.System.Keywords.decode()
		fmt.Fprintf(tw, "%s\t%s\t", flag, strings.Join(kw, ","))

		data := event.EventData.Data
		slices.SortFunc(data, func(a, b nameValue) int {
			return strings.Compare(a.Name, b.Name)
		})

		var first string
		for _, name := range []string{
			"Entry",
			"Message",
			"ErrorMessage",
		} {
			i := slices.IndexFunc(data, func(kv nameValue) bool {
				return kv.Name == name
			})

			if i == -1 {
				continue
			}

			first = data[i].Value
			data = slices.Delete(data, i, i+1)
			break
		}

		// NB: This may be empty.
		fmt.Fprintf(tw, "%s\t", first)

		for _, data := range data {
			fmt.Fprintf(tw, "%s=%s\t", data.Name, data.Value)
		}

		fmt.Fprintln(tw)
	}

	return tw.Flush()
}
