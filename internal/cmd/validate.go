// Package cmd contains the command line interface for y509
package cmd

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/kanywst/y509/internal/logger"
	"github.com/kanywst/y509/pkg/certificate"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// validateCmd represents the validate command
var validateCmd = &cobra.Command{
	Use:   "validate [target...]",
	Short: "Validate certificate chain",
	Long: `Validate the certificate chain in the specified file.

The chain is verified against the system trust store. A chain that links up but
terminates at a root which is not trusted -- an internal PKI, or a bundle that
is simply missing its root -- is reported as self-anchored rather than valid,
and exits non-zero. Pass --roots to supply your own trust anchors.

Several targets can be given at once, each a file or a live server. They are
all checked before anything exits, so one unreachable host does not hide the
rest, and the status is non-zero if any of them failed.

--json writes the whole result to stdout as JSON, which is what a script wants:
the exit code collapses "self-anchored" and "broken" into the same non-zero, and
says nothing at all about how the chain was served. One target produces the
object it always did; several produce {"targets": [...]}, so a consumer written
against the single-target shape keeps working.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		targets := args
		if len(targets) == 0 {
			// No argument: --connect, -i or stdin, resolved by loadInput.
			targets = []string{""}
		}

		asJSON, err := cmd.Flags().GetBool("json")
		if err != nil {
			return err
		}

		opts, err := verifyOptionsFromFlags(cmd)
		if err != nil {
			return err
		}

		results := make([]targetResult, 0, len(targets))
		for _, target := range targets {
			results = append(results, validateTarget(cmd, target, opts))
		}

		if asJSON {
			// Nothing else may go to stdout in this mode: the whole point is
			// that the stream parses. The non-zero exit below still reports the
			// failure, and cobra prints that to stderr.
			if err := writeResults(cmd.OutOrStdout(), results); err != nil {
				return err
			}
		} else {
			printResults(results)
		}

		return summarise(results)
	},
}

// targetResult is one target's outcome, kept so several can be reported
// together before the command decides its exit status.
type targetResult struct {
	// Target is what was asked for, empty for stdin.
	Target string
	// Err is set when the chain could not be read or verified at all, which is
	// different from a chain that was read and found wanting.
	Err error

	Source *input
	Report *certificate.ChainReport
	Result *certificate.VerifyResult
}

// name is what to print for this target.
func (r targetResult) name() string {
	if r.Target != "" {
		return r.Target
	}
	if r.Source != nil && r.Source.Host != "" {
		return r.Source.Host
	}
	return "stdin"
}

// ok reports whether this target passed. A target that could not be read at
// all counts as a failure, not as an absence.
func (r targetResult) ok() bool {
	return r.Err == nil && r.Result != nil && r.Result.Level == certificate.TrustAnchored
}

// validateTarget runs the whole check for one target, returning rather than
// exiting so the targets after it still run. A scheduled check over a fleet is
// worth more when one unreachable host does not hide the rest.
func validateTarget(cmd *cobra.Command, target string, opts certificate.VerifyOptions) targetResult {
	out := targetResult{Target: target}

	var args []string
	if target != "" {
		args = []string{target}
	}

	source, err := loadInput(cmd, args)
	if err != nil {
		logger.Log.Error("Error loading certificates", zap.String("target", target), zap.Error(err))
		out.Err = err
		return out
	}
	out.Source = source

	inputCerts := make([]*x509.Certificate, len(source.Certs))
	for i, c := range source.Certs {
		inputCerts[i] = c.Certificate
	}

	// When the chain came off the wire, check it is actually valid for the
	// host we talked to. That is the question a live endpoint raises, and it is
	// what a TLS client would ask. An explicit --host still wins.
	if opts.DNSName == "" {
		opts.DNSName = source.Host
	}

	// Look at the chain as it was presented, before sorting it: sorting is what
	// destroys the evidence. AnalyzeChain sorts it on the way through, so take
	// its result rather than sorting a second time.
	report := certificate.AnalyzeChain(inputCerts)
	if report.SortErr != nil {
		logger.Log.Error("Failed to sort certificate chain", zap.Error(report.SortErr))
		out.Err = report.SortErr
		return out
	}
	out.Report = report

	result, err := certificate.VerifyChain(report.Sorted, opts)
	if err != nil {
		logger.Log.Error("Certificate chain verification failed", zap.Error(err))
		out.Err = err
		return out
	}
	out.Result = result

	logger.Log.Info("Certificate chain validation result",
		zap.String("target", out.name()),
		zap.String("trust", result.Level.String()),
		zap.String("anchor", result.Anchor),
		zap.Int("presentationFindings", len(report.Findings)))

	return out
}

// printResults writes the text report. With one target it is exactly what it
// always was; with several, each is headed by its name so the output can be
// read top to bottom.
func printResults(results []targetResult) {
	for i, r := range results {
		if len(results) > 1 {
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("=== %s\n", r.name())
		}

		if r.Err != nil {
			fmt.Printf("❌ %v\n", r.Err)
			continue
		}

		fmt.Println(certificate.FormatVerifyResult(r.Result))

		// How the chain was presented is a separate question from whether it
		// verifies, and a chain can be perfectly trusted while still being
		// mis-served. Report it either way.
		if presentation := certificate.FormatChainReport(r.Report); presentation != "" {
			fmt.Println()
			fmt.Println(presentation)
		}

		// The verdict above is about the certificates that could be read. Say
		// so when that was not all of them, or a trusted chain would look like
		// the whole story.
		if notice := describeUnparsed(r.Source.Unparsed); notice != "" {
			fmt.Println()
			fmt.Printf("Note: %s\n", notice)
		}
	}
}

// summarise turns the outcomes into the exit status.
//
// Only a chain that reaches a real trust anchor is a success. A self-anchored
// chain gets reported, but a TLS client would not accept it, so it must not
// exit 0 and quietly pass CI.
func summarise(results []targetResult) error {
	if len(results) == 1 {
		r := results[0]
		switch {
		case r.Err != nil:
			return r.Err
		case r.ok():
			return nil
		default:
			return fmt.Errorf("certificate chain is %s", r.Result.Level)
		}
	}

	var failed []string
	for _, r := range results {
		if !r.ok() {
			failed = append(failed, r.name())
		}
	}
	if len(failed) == 0 {
		return nil
	}
	return fmt.Errorf("%d of %d targets failed: %s",
		len(failed), len(results), strings.Join(failed, ", "))
}

// writeResults writes the JSON for however many targets were asked for.
//
// One target produces the object it always did, so a consumer written against
// the single-target shape -- the GitHub Action among them -- keeps working.
// Several produce a distinct wrapper rather than an array, because an array
// and an object are different enough that a consumer fed the wrong one fails
// loudly instead of reading the first element as the whole answer.
func writeResults(w io.Writer, results []targetResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// Certificate subjects and SANs are attacker-controlled strings, and Go's
	// default HTML escaping would mangle them into \u003c sequences for no
	// benefit outside a browser.
	enc.SetEscapeHTML(false)

	if len(results) == 1 {
		// A single target that could not be read writes nothing at all, which
		// is what it did before several targets were possible. The GitHub
		// Action treats an empty report as "y509 produced nothing" and says so
		// with the stderr attached; a valid object with no trust key would slip
		// past that guard and be read as a verdict of null.
		if results[0].Err != nil {
			return nil
		}
		return encodeReport(enc, results[0])
	}

	var out struct {
		Targets []json.RawMessage `json:"targets"`
	}
	out.Targets = make([]json.RawMessage, 0, len(results))
	for _, r := range results {
		var buf bytes.Buffer
		inner := json.NewEncoder(&buf)
		inner.SetEscapeHTML(false)
		if err := encodeReport(inner, r); err != nil {
			return err
		}
		out.Targets = append(out.Targets, json.RawMessage(bytes.TrimSpace(buf.Bytes())))
	}

	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("failed to write JSON report: %w", err)
	}
	return nil
}

// encodeReport writes one target, including the one that could not be read:
// a target that failed has to appear in the output, or a consumer counting
// entries would see a fleet check quietly shrink.
func encodeReport(enc *json.Encoder, r targetResult) error {
	if r.Err != nil {
		if err := enc.Encode(struct {
			Target string `json:"target"`
			Error  string `json:"error"`
		}{Target: r.name(), Error: r.Err.Error()}); err != nil {
			return fmt.Errorf("failed to write JSON report: %w", err)
		}
		return nil
	}

	out := certificate.NewJSONReport(r.Source.Host, r.Report, r.Result)
	// Nil for a file or stdin, which leaves the object out entirely rather
	// than reporting a handshake that never happened.
	out.Connection = certificate.NewJSONConnection(r.Source.Conn)
	// Nil when everything parsed, which leaves the key out entirely.
	out.Unparsed = certificate.NewJSONUnparsed(r.Source.Unparsed)

	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("failed to write JSON report: %w", err)
	}
	return nil
}

// verifyOptionsFromFlags builds the verification options from the trust flags.
func verifyOptionsFromFlags(cmd *cobra.Command) (certificate.VerifyOptions, error) {
	var opts certificate.VerifyOptions

	skipSystem, err := cmd.Flags().GetBool("no-system-roots")
	if err != nil {
		return opts, err
	}
	opts.SkipSystemRoots = skipSystem

	hostname, err := cmd.Flags().GetString("host")
	if err != nil {
		return opts, err
	}
	opts.DNSName = hostname

	rootsFile, err := cmd.Flags().GetString("roots")
	if err != nil {
		return opts, err
	}
	if rootsFile != "" {
		roots, unparsed, err := loadCertificateFile(cmd, rootsFile)
		if err != nil {
			return opts, fmt.Errorf("failed to load trust anchors from %s: %w", rootsFile, err)
		}
		// Skipping an unreadable certificate is right for the chain under
		// inspection and wrong for a trust anchor. The caller named this file
		// as the set to trust, so quietly trusting a subset of it would change
		// the verdict with nothing on screen to say why.
		if len(unparsed) > 0 {
			return opts, fmt.Errorf(
				"failed to load trust anchors from %s: %s",
				rootsFile, describeUnparsed(unparsed))
		}
		for _, root := range roots {
			opts.ExtraRoots = append(opts.ExtraRoots, root.Certificate)
		}
	}

	if opts.SkipSystemRoots && len(opts.ExtraRoots) == 0 {
		return opts, fmt.Errorf("--no-system-roots leaves no trust anchors; pass --roots as well")
	}

	return opts, nil
}

func init() {
	validateCmd.Flags().String("roots", "", "PEM file of additional trust anchors")
	validateCmd.Flags().Bool("no-system-roots", false, "Do not trust the system store; use only --roots")
	validateCmd.Flags().String("host", "", "Also check that the leaf is valid for this hostname")
	validateCmd.Flags().Bool("json", false, "Emit the result as JSON instead of text")
	RootCmd.AddCommand(validateCmd)
}
