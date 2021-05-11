package spdx

import (
	"bytes"
	"html/template"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"sigs.k8s.io/release-utils/hash"
	"sigs.k8s.io/release-utils/util"
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
	FileName          string // Name of the file
	ID                string // SPDXRef-Makefile
	LicenseConcluded  string // GPL-3.0-or-later
	LicenseInfoInFile string // GPL-3.0-or-later
	CopyrightText     string // NOASSERTION
	SourceFile        string // Source file to read from (not part of the spec)
	Checksum          map[string]string

	options *FileOptions // Options
}

func NewFile() (f *File) {
	f = &File{
		options: &FileOptions{},
	}
	return f
}

func (f *File) Options() *FileOptions {
	return f.options
}

// FileOptions
type FileOptions struct {
	WorkDir string
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
	s256, err := hash.SHA256ForFile(filePath)
	if err != nil {
		return errors.Wrap(err, "getting file checksums")
	}
	s512, err := hash.SHA512ForFile(filePath)
	if err != nil {
		return errors.Wrap(err, "getting file checksums")
	}

	f.Checksum = map[string]string{
		"SHA256": s256,
		"SHA512": s512,
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

// ReadSourceFile reads the source file for the package and populates
//  the fields derived from it (Checksums and FileName)
func (f *File) ReadSourceFile(path string) error {
	if !util.Exists(path) {
		return errors.New("unable to find package source file")
	}

	s256, err := hash.SHA256ForFile(path)
	if err != nil {
		return errors.Wrap(err, "getting source file sha256")
	}
	s512, err := hash.SHA512ForFile(path)
	if err != nil {
		return errors.Wrap(err, "getting source file sha512")
	}
	f.Checksum = map[string]string{
		"SHA256": s256,
		"SHA512": s512,
	}
	f.SourceFile = path
	f.FileName = strings.TrimPrefix(path, f.Options().WorkDir+string(filepath.Separator))
	return nil
}
