package cmd

import (
	"crypto/x509"
	"fmt"

	"github.com/kanywst/y509/internal/logger"
	"github.com/kanywst/y509/pkg/certificate"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var diffCmd = &cobra.Command{
	Use:   "diff <a> <b>",
	Short: "Compare two certificate chains",
	Long: `Compare two chains as they were presented.

Each argument is a file or a live server, resolved exactly as the other
commands resolve theirs. Certificates are matched by the SHA-256 of their DER
rather than by subject, because a renewed certificate keeps its name and
changes everything else.

The exit status follows diff(1): 0 when the chains are identical, 1 when they
differ. That makes it usable as a check that a rotation did or did not happen.

  y509 diff before.pem after.pem
  y509 diff node1.example.com:443 node2.example.com:443`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		before, err := loadDiffSide(cmd, args[0])
		if err != nil {
			return fmt.Errorf("reading %s: %w", args[0], err)
		}
		after, err := loadDiffSide(cmd, args[1])
		if err != nil {
			return fmt.Errorf("reading %s: %w", args[1], err)
		}

		diff := certificate.DiffChains(before, after)
		fmt.Println(certificate.FormatChainDiff(diff))

		logger.Log.Info("Compared two chains",
			zap.Int("before", len(before)),
			zap.Int("after", len(after)),
			zap.Bool("identical", diff.Same()))

		if !diff.Same() {
			// diff(1)'s convention. A difference is not an error, so nothing is
			// printed to stderr; the status is there for a script that wants to
			// know whether anything changed.
			return errChainsDiffer
		}
		return nil
	},
	// The exit status carries the answer, so cobra must not also print the
	// sentinel as though something went wrong.
	SilenceErrors: true,
}

// errChainsDiffer reports a difference through the exit status without being an
// error anyone needs to read.
var errChainsDiffer = fmt.Errorf("the chains differ")

// loadDiffSide resolves one side of the comparison. The targets are positional
// here rather than flags, so each is passed to loadInput on its own.
func loadDiffSide(cmd *cobra.Command, target string) ([]*x509.Certificate, error) {
	source, err := loadInput(cmd, []string{target})
	if err != nil {
		return nil, err
	}

	certs := make([]*x509.Certificate, 0, len(source.Certs))
	for _, c := range source.Certs {
		certs = append(certs, c.Certificate)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}
	return certs, nil
}

func init() {
	RootCmd.AddCommand(diffCmd)
}
