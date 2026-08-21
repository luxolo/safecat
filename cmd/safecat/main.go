package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"github.com/luxolo/safecat"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	exitOK         = 0
	exitUsage      = 2
	exitIO         = 3
	exitProcessing = 4
	exitPolicy     = 5
)

type options struct {
	format, replacement, literal, policyFile, policyName, color string
	strict, explain                                             bool
}

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--version" || args[0] == "-v" || args[0] == "version") {
		fmt.Fprintf(stdout, "safecat %s\n", safecat.Version)
		return exitOK
	}
	if len(args) > 0 && args[0] == "init" {
		return runInit(args[1:], stdout, stderr)
	}
	if len(args) > 1 && args[0] == "config" {
		return runConfigCommand(args[1:], stdout, stderr)
	}
	if len(args) > 1 && args[0] == "policy" && args[1] == "list" {
		return runPolicyList(args[2:], stdout, stderr)
	}
	fs := flag.NewFlagSet("safecat", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	o := options{}
	fs.StringVar(&o.format, "format", "auto", "input format: auto, plain, yaml, or json")
	fs.StringVar(&o.replacement, "replacement", "", "replacement: literal, mask, or hash")
	fs.StringVar(&o.literal, "literal", "", "literal replacement text")
	fs.StringVar(&o.policyFile, "policy-file", "", "JSON policy file")
	fs.StringVar(&o.policyName, "policy", "", "persistent policy name")
	fs.BoolVar(&o.strict, "strict", false, "fail if suspicious content remains or certainty is unavailable")
	fs.BoolVar(&o.explain, "explain", false, "report rule names and byte/line locations to stderr")
	fs.StringVar(&o.color, "color", "auto", "explain color: auto, always, or never")
	fs.Usage = func() { printHelp(stderr) }
	if containsHelp(args) {
		printHelp(stdout)
		return exitOK
	}
	if err := fs.Parse(args); err != nil {
		printHelp(stderr)
		return exitUsage
	}
	if !validOption(o) {
		fmt.Fprintln(stderr, "safecat: invalid option")
		return exitUsage
	}
	paths, err := safecat.UserConfigPaths()
	if err != nil {
		fmt.Fprintln(stderr, "safecat: configuration unavailable")
		return exitPolicy
	}
	project, err := safecat.ProjectPolicy()
	if err != nil {
		fmt.Fprintln(stderr, "safecat: configuration unavailable")
		return exitPolicy
	}
	policy, _, err := safecat.LoadEffectivePolicy(paths, project, o.policyName, o.policyFile)
	if err != nil {
		fmt.Fprintln(stderr, "safecat: policy error")
		return exitPolicy
	}
	if o.replacement != "" {
		policy.Replacement = o.replacement
	}
	if o.literal != "" {
		policy.Literal = o.literal
	}
	if err := policy.Validate(); err != nil {
		fmt.Fprintln(stderr, "safecat: policy error")
		return exitPolicy
	}
	names := fs.Args()
	if len(names) == 0 {
		names = []string{"-"}
	}
	for _, name := range names {
		var src io.Reader = stdin
		var file *os.File
		if name != "-" {
			var err error
			file, err = os.Open(name)
			if err != nil {
				fmt.Fprintln(stderr, "safecat: input error")
				return exitIO
			}
			src = file
		}
		code := processInput(src, stdout, stderr, name, o, policy)
		if file != nil {
			_ = file.Close()
		}
		if code != exitOK {
			return code
		}
	}
	return exitOK
}

func processInput(src io.Reader, stdout, stderr io.Writer, name string, o options, policy safecat.Policy) int {
	_ = name
	if o.format == "auto" && !o.strict && !o.explain {
		reader := bufio.NewReaderSize(src, 32<<10)
		prefix := make([]byte, 32<<10)
		n, err := reader.Read(prefix)
		if err != nil && err != io.EOF {
			fmt.Fprintln(stderr, "safecat: input error")
			return exitIO
		}
		if safecat.DetectFormat(prefix[:n]) == safecat.FormatUnknown {
			return streamInput(io.MultiReader(bytes.NewReader(prefix[:n]), reader), stdout, stderr, policy)
		}
		src = io.MultiReader(bytes.NewReader(prefix[:n]), reader)
		o.format = string(safecat.DetectFormat(prefix[:n]))
	}
	if o.strict || o.explain || o.format != "plain" {
		limit := int64(safecat.DefaultStructuredOptions().MaxBytes) + 1
		data, err := io.ReadAll(io.LimitReader(src, limit))
		if err != nil {
			fmt.Fprintln(stderr, "safecat: input error")
			return exitIO
		}
		if len(data) > int(limit-1) {
			if o.format == "auto" && !o.strict && !o.explain {
				return streamInput(io.MultiReader(bytes.NewReader(data), src), stdout, stderr, policy)
			}
			fmt.Fprintln(stderr, "safecat: processing error")
			return exitProcessing
		}
		format := o.format
		if format == "auto" {
			format = string(safecat.DetectFormat(data))
		}
		var out []byte
		if format == "plain" {
			var buf bytes.Buffer
			if code := streamInput(bytes.NewReader(data), &buf, stderr, policy); code != exitOK {
				return code
			}
			out = buf.Bytes()
		} else {
			structuredFormat := safecat.FormatAuto
			if format == "yaml" {
				structuredFormat = safecat.FormatYAML
			} else if format == "json" {
				structuredFormat = safecat.FormatJSON
			}
			out, err = safecat.RedactStructuredAs(data, safecat.DefaultStructuredOptions(), structuredFormat, policy)
			if err != nil {
				fmt.Fprintln(stderr, "safecat: processing error")
				return exitProcessing
			}
		}
		if o.explain {
			printExplain(stderr, policy.Explain(data), o.color)
		}
		if o.strict {
			if matches, _ := policy.CustomRegistry().Detect(out); len(matches) > 0 {
				fmt.Fprintln(stderr, "safecat: strict mode unresolved content")
				return exitProcessing
			}
		}
		if err := writeAll(stdout, out); err != nil {
			return exitIO
		}
		return exitOK
	}
	return streamInput(src, stdout, stderr, policy)
}

func streamInput(src io.Reader, dst io.Writer, stderr io.Writer, policy safecat.Policy) int {
	if err := safecat.Stream(src, dst, safecat.NewEngine(policy.Registry(), policy.Redaction()), 32<<10); err != nil {
		fmt.Fprintln(stderr, "safecat: processing error")
		if errors.Is(err, safecat.ErrLimitExceeded) || errors.Is(err, safecat.ErrInvalidMatch) {
			return exitProcessing
		}
		return exitIO
	}
	return exitOK
}
func writeAll(dst io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := dst.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
func printExplain(w io.Writer, rules []safecat.RuleExplanation, color string) {
	for _, rule := range rules {
		name := rule.Rule
		if color == "always" {
			name = "\033[36m" + name + "\033[0m"
		}
		fmt.Fprintf(w, "rule=%s location=%s\n", name, rule.Location)
	}
}
func containsHelp(args []string) bool {
	for _, arg := range args {
		if arg == "--help" || arg == "-h" {
			return true
		}
	}
	return false
}
func validOption(o options) bool {
	return (o.format == "auto" || o.format == "plain" || o.format == "yaml" || o.format == "json") && (o.replacement == "" || o.replacement == "literal" || o.replacement == "mask" || o.replacement == "hash") && (o.color == "auto" || o.color == "always" || o.color == "never") && (o.policyName == "" || safecat.ValidatePolicyName(o.policyName))
}
func printHelp(w io.Writer) {
	fmt.Fprintln(w, `Usage: safecat [OPTIONS] [FILE ...]

Read stdin when no FILE is supplied; use - as FILE for stdin explicitly.

Options:
  --format auto|plain|yaml|json  choose detection (default auto)
  --replacement literal|mask|hash replacement strategy
  --literal TEXT                 literal replacement (default REDACTED)
  --policy-file FILE             JSON policy file
  --policy NAME                  persistent policy from the user policy directory
  --version                      show the safecat version
  --strict                       fail on unresolved suspicious content
  --explain                      report rule names and safe locations on stderr
  --color auto|always|never      color explain output (default auto)
  -h, --help                    show this help

Examples:
  kubectl get secret -o yaml | safecat
  safecat --format yaml kubeconfig
  safecat --policy-file policy.json < input.txt`)
}

func runInit(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(stdout, "Usage: safecat init [--force]")
		return exitOK
	}
	fs := flag.NewFlagSet("safecat init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	force := fs.Bool("force", false, "replace the starter config file")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "safecat init: invalid arguments")
		return exitUsage
	}
	paths, err := safecat.UserConfigPaths()
	if err != nil {
		fmt.Fprintln(stderr, "safecat: configuration unavailable")
		return exitPolicy
	}
	if err := safecat.InitConfig(paths, *force); err != nil {
		if errors.Is(err, os.ErrExist) {
			fmt.Fprintln(stderr, "safecat: configuration already exists; use --force only for the starter config")
		} else {
			fmt.Fprintln(stderr, "safecat: unable to initialize configuration")
		}
		return exitPolicy
	}
	fmt.Fprintln(stdout, paths.Base)
	return exitOK
}

func runConfigCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, "Usage: safecat config path|show")
		return exitOK
	}
	paths, err := safecat.UserConfigPaths()
	if err != nil {
		fmt.Fprintln(stderr, "safecat: configuration unavailable")
		return exitPolicy
	}
	switch args[0] {
	case "path":
		if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
			fmt.Fprintln(stdout, "Usage: safecat config path")
			return exitOK
		}
		if len(args) != 1 {
			fmt.Fprintln(stderr, "safecat config path: invalid arguments")
			return exitUsage
		}
		fmt.Fprintln(stdout, paths.Base)
		return exitOK
	case "show":
		if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
			fmt.Fprintln(stdout, "Usage: safecat config show")
			return exitOK
		}
		if len(args) != 1 {
			fmt.Fprintln(stderr, "safecat config show: invalid arguments")
			return exitUsage
		}
		project, err := safecat.ProjectPolicy()
		if err != nil {
			fmt.Fprintln(stderr, "safecat: configuration unavailable")
			return exitPolicy
		}
		policy, origins, err := safecat.LoadEffectivePolicy(paths, project, "", "")
		if err != nil {
			fmt.Fprintln(stderr, "safecat: policy error")
			return exitPolicy
		}
		fmt.Fprintf(stdout, "version: %d\nconfig_dir: %s\nreplacement: %s\nsensitive_keys: %d\nsensitive_paths: %d\nregex_rules: %d\norigins:\n", safecat.ConfigVersion, paths.Base, policy.Replacement, len(policy.SensitiveKeys), len(policy.SensitivePaths), len(policy.Regex))
		for _, origin := range origins {
			fmt.Fprintf(stdout, "  - %s (%s)\n", origin.Name, origin.Path)
		}
		return exitOK
	default:
		fmt.Fprintln(stderr, "safecat config: unknown command")
		return exitUsage
	}
}

func runPolicyList(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(stdout, "Usage: safecat policy list")
		return exitOK
	}
	if len(args) != 0 {
		fmt.Fprintln(stderr, "safecat policy list: invalid arguments")
		return exitUsage
	}
	paths, err := safecat.UserConfigPaths()
	if err != nil {
		fmt.Fprintln(stderr, "safecat: configuration unavailable")
		return exitPolicy
	}
	items, err := safecat.LoadPersistentPolicies(paths, "")
	if err != nil {
		fmt.Fprintln(stderr, "safecat: policy error")
		return exitPolicy
	}
	if len(items) == 0 {
		fmt.Fprintln(stdout, "No persistent policies found.")
		return exitOK
	}
	sort.Slice(items, func(i, j int) bool {
		return strings.Compare(filepath.Base(items[i].Path), filepath.Base(items[j].Path)) < 0
	})
	for _, item := range items {
		if item.Err != nil {
			fmt.Fprintf(stdout, "%s\tinvalid\n", item.Name)
		} else {
			fmt.Fprintf(stdout, "%s\tvalid\n", item.Name)
		}
	}
	return exitOK
}
