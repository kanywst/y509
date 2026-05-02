package model

import (
	"errors"
	"strings"

	"charm.land/huh/v2"
)

// newExportForm builds a fresh huh form for the export popup. Two fields:
// a required filename and a format selector. The filename validator
// rejects blank input so the form cannot complete with an empty value
// and leave the export popup wedged.
func newExportForm() *huh.Form {
	return huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Key("filename").
				Title("Filename").
				Placeholder("cert").
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return errors.New("filename is required")
					}
					return nil
				}),
			huh.NewSelect[string]().
				Key("format").
				Title("Format").
				Options(
					huh.NewOption("PEM", "pem"),
					huh.NewOption("DER", "der"),
					huh.NewOption("CRT", "crt"),
				),
		),
	).WithShowHelp(false).WithShowErrors(true)
}
