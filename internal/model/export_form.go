package model

import "charm.land/huh/v2"

// newExportForm builds a fresh huh form for the export popup. Two fields:
// a free-form filename and a format selector. The format selector defaults
// to PEM and feeds the file extension that handleExportCommand cares about.
func newExportForm() *huh.Form {
	return huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Key("filename").
				Title("Filename").
				Placeholder("cert"),
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
