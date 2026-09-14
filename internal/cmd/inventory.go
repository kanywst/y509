package cmd

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/kanywst/y509/internal/logger"
	"github.com/kanywst/y509/pkg/certificate"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var inventoryCmd = &cobra.Command{
	Use:   "inventory [target...]",
	Short: "List the cryptography in use across several targets",
	Long: `List what algorithm, key size and lifetime each target is using.

This answers "what have we got", not "is it valid": nothing here is verified
against a trust store, and the command exits 0 for anything it could read. It
is the shape an audit wants -- PCI DSS asks for an inventory of certificates
and keys, and a post-quantum migration starts by finding every RSA key.

  y509 inventory www.example.com:443 api.example.com:443
  y509 inventory chain.pem --csv > inventory.csv`,
	RunE: func(cmd *cobra.Command, args []string) error {
		targets := args
		if len(targets) == 0 {
			targets = []string{""}
		}

		asJSON, err := cmd.Flags().GetBool("json")
		if err != nil {
			return err
		}
		asCSV, err := cmd.Flags().GetBool("csv")
		if err != nil {
			return err
		}
		if asJSON && asCSV {
			return fmt.Errorf("give either --json or --csv, not both")
		}

		var rows []inventoryRow
		var failures []string
		for _, target := range targets {
			var args []string
			if target != "" {
				args = []string{target}
			}

			source, err := loadInput(cmd, args)
			if err != nil {
				// One unreachable target must not hide the rest, and an
				// inventory with a hole in it is worse than one that says
				// where the hole is.
				logger.Log.Error("Could not read a target",
					zap.String("target", target), zap.Error(err))
				failures = append(failures, fmt.Sprintf("%s: %v", displayTarget(target), err))
				continue
			}
			targetRows := inventoryRows(displayTarget(target), source)
			// By position, so an unreadable certificate sits where it was in
			// the input rather than at the top.
			sort.SliceStable(targetRows, func(i, j int) bool {
				return targetRows[i].Position < targetRows[j].Position
			})
			rows = append(rows, targetRows...)
		}

		switch {
		case asJSON:
			if err := writeInventoryJSON(cmd.OutOrStdout(), rows, failures); err != nil {
				return err
			}
		case asCSV:
			if err := writeInventoryCSV(cmd.OutOrStdout(), rows); err != nil {
				return err
			}
		default:
			writeInventoryText(rows, failures)
		}

		if len(failures) > 0 {
			return fmt.Errorf("%d of %d targets could not be read", len(failures), len(targets))
		}
		return nil
	},
}

// inventoryRow is one certificate, reduced to what an audit asks about.
//
// A certificate that could not be parsed still gets a row, carrying Unreadable
// and nothing else. An inventory that silently counts fewer certificates than
// the input holds is the one failure an auditor would never notice.
type inventoryRow struct {
	// Unreadable is the parser's error for a CERTIFICATE block that could not
	// be read, and empty for every row that describes a real certificate.
	Unreadable string `json:"unreadable,omitempty"`

	Target             string `json:"target"`
	Position           int    `json:"position"`
	CommonName         string `json:"commonName"`
	Issuer             string `json:"issuer"`
	KeyAlgorithm       string `json:"keyAlgorithm"`
	KeyBits            int    `json:"keyBits,omitempty"`
	SignatureAlgorithm string `json:"signatureAlgorithm"`
	NotAfter           string `json:"notAfter"`
	DaysUntilExpiry    int    `json:"daysUntilExpiry"`
	LifetimeDays       int    `json:"lifetimeDays"`
	IsCA               bool   `json:"isCa"`
	FingerprintSHA256  string `json:"fingerprintSha256"`
}

// displayTarget names a target for the output, including the one that came
// from stdin and has no name of its own.
func displayTarget(target string) string {
	if target == "" {
		return "stdin"
	}
	return target
}

// inventoryRows turns one target's chain into rows, in the order it was
// presented, including a row for each certificate that could not be read.
func inventoryRows(target string, source *input) []inventoryRow {
	rows := make([]inventoryRow, 0, len(source.Certs)+len(source.Unparsed))
	for _, failure := range source.Unparsed {
		row := inventoryRow{
			Target:     target,
			Position:   failure.Block,
			CommonName: "(unreadable)",
			Unreadable: "could not be parsed",
		}
		if failure.Err != nil {
			row.Unreadable = failure.Err.Error()
		}
		rows = append(rows, row)
	}

	for _, info := range source.Certs {
		cert := info.Certificate
		rows = append(rows, inventoryRow{
			Target: target,
			// Info.Index, not the loop counter: source.Certs holds only what
			// parsed, so the counter is contiguous while Index -- like the
			// ParseFailure.Block used for the unreadable rows above -- counts
			// every CERTIFICATE block. Mixing the two puts two rows at the
			// same position and sorts them into the wrong order.
			Position:           info.Index,
			CommonName:         cert.Subject.CommonName,
			Issuer:             cert.Issuer.CommonName,
			KeyAlgorithm:       cert.PublicKeyAlgorithm.String(),
			KeyBits:            certificate.PublicKeyBits(cert),
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
			NotAfter:           cert.NotAfter.UTC().Format("2006-01-02"),
			DaysUntilExpiry:    certificate.DaysUntilExpiry(cert),
			LifetimeDays:       certificate.ValidityPeriodDays(cert),
			IsCA:               cert.IsCA,
			FingerprintSHA256:  certificate.FormatFingerprint(cert),
		})
	}
	return rows
}

func writeInventoryJSON(w io.Writer, rows []inventoryRow, failures []string) error {
	out := struct {
		Certificates []inventoryRow `json:"certificates"`
		Unreadable   []string       `json:"unreadable,omitempty"`
	}{Certificates: rows, Unreadable: failures}
	if out.Certificates == nil {
		out.Certificates = []inventoryRow{}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("failed to write JSON: %w", err)
	}
	return nil
}

// writeInventoryCSV writes the rows for a spreadsheet, which is what an
// auditor asks for more often than JSON.
func writeInventoryCSV(w io.Writer, rows []inventoryRow) error {
	out := csv.NewWriter(w)
	header := []string{
		"target", "position", "common_name", "issuer", "key_algorithm", "key_bits",
		"signature_algorithm", "not_after", "days_until_expiry", "lifetime_days",
		"is_ca", "fingerprint_sha256", "unreadable",
	}
	if err := out.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV: %w", err)
	}

	for _, r := range rows {
		record := []string{
			r.Target, strconv.Itoa(r.Position), r.CommonName, r.Issuer,
			r.KeyAlgorithm, keyBitsField(r.KeyBits), r.SignatureAlgorithm,
			r.NotAfter, strconv.Itoa(r.DaysUntilExpiry), strconv.Itoa(r.LifetimeDays),
			strconv.FormatBool(r.IsCA), r.FingerprintSHA256, r.Unreadable,
		}
		if err := out.Write(record); err != nil {
			return fmt.Errorf("failed to write CSV: %w", err)
		}
	}

	out.Flush()
	if err := out.Error(); err != nil {
		return fmt.Errorf("failed to write CSV: %w", err)
	}
	return nil
}

// keyBitsField leaves the cell empty rather than writing 0 for a key whose
// size is not a number -- Ed25519, and anything crypto/x509 did not decode.
func keyBitsField(bits int) string {
	if bits == 0 {
		return ""
	}
	return strconv.Itoa(bits)
}

func writeInventoryText(rows []inventoryRow, failures []string) {
	if len(rows) == 0 && len(failures) == 0 {
		fmt.Println("No certificates found.")
		return
	}

	widths := []int{len("TARGET"), len("SUBJECT"), len("KEY"), len("SIGNATURE"), len("EXPIRES"), len("DAYS")}
	cells := make([][]string, 0, len(rows))
	for _, r := range rows {
		row := []string{
			r.Target,
			r.CommonName,
			keyDescription(r),
			r.SignatureAlgorithm,
			r.NotAfter,
			strconv.Itoa(r.DaysUntilExpiry),
		}
		for i, c := range row {
			if len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
		cells = append(cells, row)
	}

	printRow := func(cols []string) {
		var sb strings.Builder
		for i, c := range cols {
			if i > 0 {
				sb.WriteString("  ")
			}
			sb.WriteString(c)
			sb.WriteString(strings.Repeat(" ", widths[i]-len(c)))
		}
		fmt.Println(strings.TrimRight(sb.String(), " "))
	}

	printRow([]string{"TARGET", "SUBJECT", "KEY", "SIGNATURE", "EXPIRES", "DAYS"})
	for _, row := range cells {
		printRow(row)
	}

	for _, f := range failures {
		fmt.Printf("\n❌ %s\n", f)
	}
}

// keyDescription is the algorithm and size together, which is the pair an
// inventory is actually looking for.
func keyDescription(r inventoryRow) string {
	if r.Unreadable != "" {
		return "unreadable"
	}
	if r.KeyBits == 0 {
		return r.KeyAlgorithm
	}
	return fmt.Sprintf("%s %d", r.KeyAlgorithm, r.KeyBits)
}

func init() {
	inventoryCmd.Flags().Bool("json", false, "Emit the inventory as JSON")
	inventoryCmd.Flags().Bool("csv", false, "Emit the inventory as CSV")
	RootCmd.AddCommand(inventoryCmd)
}
