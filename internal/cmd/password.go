package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/kanywst/y509/pkg/certificate"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// pkcs12PasswordEnv is where a script puts the password. An environment
// variable rather than a flag: a flag value is visible in ps to every user on
// the host, and a certificate bundle's password is worth more than that.
const pkcs12PasswordEnv = "Y509_PKCS12_PASSWORD"

// errPKCS12Needed marks a failure that is about the password rather than the
// format, so loadInput can report it instead of falling back to a message
// about the input not being a certificate.
var errPKCS12Needed = fmt.Errorf("pkcs12")

// loadPKCS12 reads a PKCS#12 file, asking for a password only if it needs one.
//
// The empty password is tried first because a bundle exported purely to move
// certificates around often has none, and asking for a password that is not
// needed trains people to type one anywhere.
func loadPKCS12(cmd *cobra.Command, data []byte) ([]*certificate.Info, error) {
	certs, err := certificate.ParsePKCS12(data, "")
	if err == nil {
		return certs, nil
	}
	if err != certificate.ErrPKCS12Password {
		return nil, err
	}

	password, err := pkcs12Password(cmd)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errPKCS12Needed, err)
	}

	certs, err = certificate.ParsePKCS12(data, password)
	if err == certificate.ErrPKCS12Password {
		return nil, fmt.Errorf("%w: incorrect password for the PKCS#12 file", errPKCS12Needed)
	}
	return certs, err
}

// pkcs12Password finds a password: a file named on the command line, the
// environment, or the terminal.
func pkcs12Password(cmd *cobra.Command) (string, error) {
	passwordFile, err := cmd.Flags().GetString("password-file")
	if err != nil {
		return "", err
	}
	if passwordFile != "" {
		raw, err := os.ReadFile(passwordFile) //nolint:gosec // the path is the user's own
		if err != nil {
			return "", fmt.Errorf("reading the password file: %w", err)
		}
		// A trailing newline is what an editor leaves behind and is almost
		// never part of the password.
		return strings.TrimRight(string(raw), "\r\n"), nil
	}

	if password, ok := os.LookupEnv(pkcs12PasswordEnv); ok {
		return password, nil
	}

	return promptForPassword()
}

// promptForPassword reads a password from the terminal.
//
// From /dev/tty rather than standard input, because standard input may be the
// certificate bundle itself -- and the prompt goes to standard error so it
// cannot end up inside piped output.
func promptForPassword() (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf(
			"this PKCS#12 file needs a password: set %s, pass --password-file, "+
				"or run where a terminal is available", pkcs12PasswordEnv)
	}
	defer func() { _ = tty.Close() }()

	fmt.Fprint(os.Stderr, "PKCS#12 password: ")
	password, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading the password: %w", err)
	}
	return string(password), nil
}
