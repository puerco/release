package spdx

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"html/template"
	"io"
	"os"

	"github.com/pkg/errors"
)

var fileTemplate = `{{ if .Name }}FileName: {{ .Name }}
{{ end -}}
{{ if .ID }}SPDXID: {{ .ID }}
{{ end -}}
{{- if .Checksum -}}
{{- range $key, $value := .Checksum -}}
{{ if . }}FileChecksum: {{ $key }}: {{ $value }}
{{ end -}}
{{- end -}}
{{- end -}}
{{ if .LicenseConcluded }}LicenseConcluded: {{ .LicenseConcluded }}
{{ end -}}
{{ if .LicenseInfoInFile }}LicenseInfoInFile: {{ .LicenseInfoInFile }}
{{ end -}}
{{ if .CopyrightText }}CopyrightText: {{ .CopyrightText }}
{{ end -}}

`

// File abstracts a file contained in a package
type File struct {
	Name              string // string /Makefile
	ID                string // SPDXRef-Makefile
	LicenseConcluded  string // GPL-3.0-or-later
	LicenseInfoInFile string // GPL-3.0-or-later
	CopyrightText     string // NOASSERTION
	Checksum          map[string]string
}

// ReadChecksums receives a path to a file and calculates its checksums
func (f *File) ReadChecksums(filePath string) error {
	if f.Checksum == nil {
		f.Checksum = map[string]string{}
	}
	file, err := os.Open(filePath)
	if err != nil {
		return errors.Wrap(err, "opening file for reading: "+filePath)
	}
	defer file.Close()
	for _, h := range []hash.Hash{sha1.New(), sha256.New(), sha512.New()} {
		checksum, err := func(f *os.File, h hash.Hash, filePath string) (sum string, err error) {
			if _, err := f.Seek(0, 0); err != nil {
				return "", errors.Wrap(err, "seeking file")
			}
			if _, err := io.Copy(h, f); err != nil {
				return "", errors.Wrap(err, "writing file contests to hasher")
			}
			return fmt.Sprintf("%x", h.Sum(nil)), nil
		}(file, h, filePath)
		if err != nil {
			return errors.Wrap(err, "calculating checksum of file")
		}
		if h.Size() == 20 {
			f.Checksum["SHA1"] = checksum
		} else {
			f.Checksum[fmt.Sprintf("SHA%d", h.Size()*8)] = checksum
		}
	}
	return nil
}

// Render renders the document fragment of a file
func (f *File) Render() (docFragment string, err error) {
	var buf bytes.Buffer
	tmpl, err := template.New("file").Parse(fileTemplate)
	if err != nil {
		return "", errors.Wrap(err, "parsing file template")
	}

	// Run the template to verify the output.
	if err := tmpl.Execute(&buf, f); err != nil {
		return "", errors.Wrap(err, "executing spdx file template")
	}

	docFragment = buf.String()
	return docFragment, nil
}
