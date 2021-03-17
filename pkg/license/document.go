/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package license

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"html/template"
	"io"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"
)

const (
	defaultDocumentAuthor = "Kubernetes Release Managers (release-managers@kubernetes.io)"
)

var docTemplate = `{{ if .Version }}SPDXVersion: {{.Version}}
{{ end -}}
{{ if .ID }}SPDXID: {{ .ID }}
{{ end -}}
{{ if .Name }}DocumentName: {{ .Name }}
{{ end -}}
{{ if .Namespace }}DocumentNamespace: {{ .Namespace }}
{{ end -}}
{{ if .Creator -}}
{{- if .Creator.Person }}Creator: Person: {{ .Creator.Person }}
{{ end -}}
{{- if .Creator.Tool -}}
{{- range $key, $value := .Creator.Tool }}Creator: Tool: {{ $value }}
{{ end -}}
{{- end -}}
{{ end -}}
{{ if .Created }}Created: {{ dateFormat .Created }}
{{ end }}

`

var packageTemplate = `##### Package: {{ .Name }}

{{ if .Name }}PackageName: {{ .Name }}
{{ end -}}
{{ if .ID }}SPDXID: {{ .ID }}
{{ end -}}
{{ if .DownloadLocation }}PackageDownloadLocation: {{ .DownloadLocation }}
{{ end -}}
FilesAnalyzed: {{ .FilesAnalyzed }}
{{ if .VerificationCode }}PackageVerificationCode: {{ .VerificationCode }}
{{ end -}}
{{ if .LicenseConcluded }}PackageLicenseConcluded: {{ .LicenseConcluded }}
{{ end -}}
{{ if .FileName }}PackageFileName: {{ .FileName }}
{{ end -}}
{{ if .LicenseInfoFromFiles }}PackageLicenseInfoFromFiles: {{ .LicenseInfoFromFiles }}
{{ end -}}
{{ if .Version }}PackageVersion: {{ .Version }}
{{ end -}}
PackageLicenseDeclared: {{ if .LicenseDeclared }}{{ .LicenseDeclared }}{{ else }}NOASSERTION{{ end }}
{{ if .CopyrightText }}PackageCopyrightText: <text>{{ .CopyrightText }}
</text>{{ end }}
`

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

// Document abstracts the SPDX document
type Document struct {
	Version     string // SPDX-2.2
	DataLicense string // CC0-1.0
	ID          string // SPDXRef-DOCUMENT
	Name        string // hello-go-src
	Namespace   string // https://swinslow.net/spdx-examples/example6/hello-go-src-v1
	Creator     struct {
		Person string   // Steve Winslow (steve@swinslow.net)
		Tool   []string // github.com/spdx/tools-golang/builder
	}
	Created  time.Time // 2020-11-24T01:12:27Z
	Packages map[string]*Package
}

// Package groups a set of files
type Package struct {
	FilesAnalyzed        bool   // true
	Name                 string // hello-go-src
	ID                   string // SPDXRef-Package-hello-go-src
	DownloadLocation     string // git@github.com:swinslow/spdx-examples.git#example6/content/src
	VerificationCode     string // 6486e016b01e9ec8a76998cefd0705144d869234
	LicenseConcluded     string // LicenseID o NOASSERTION
	LicenseInfoFromFiles string // GPL-3.0-or-later
	LicenseDeclared      string // GPL-3.0-or-later
	LicenseComments      string // record any relevant background information or analysis that went in to arriving at the Concluded License
	CopyrightText        string // string NOASSERTION
	Version              string // Package version
	FileName             string // Name of the package
	// Supplier: the actual distribution source for the package/directory
	Supplier struct {
		Person       string // person name and optional (<email>)
		Organization string // organization name and optional (<email>)
	}
	// Originator: For example, the SPDX file identifies the package glibc and Red Hat as the Package Supplier,
	// but the Free Software Foundation is the Package Originator.
	Originator struct {
		Person       string // person name and optional (<email>)
		Organization string // organization name and optional (<email>)
	}
	// Subpackages contained
	Packages map[string]*Package // Sub packages conatined in this pkg
	Files    map[string]*File
}

// File abstracts a file contained in a package
type File struct {
	Name              string // string /Makefile
	ID                string // SPDXRef-Makefile
	LicenseConcluded  string // GPL-3.0-or-later
	LicenseInfoInFile string // GPL-3.0-or-later
	CopyrightText     string // NOASSERTION
	Checksum          map[string]string
}

// NewDocument returns a new SPDX document with some defaults preloaded
func (spdx *SPDX) NewDocument() *Document {
	return &Document{
		Version:     "SPDX-2.2",
		DataLicense: "CC0-1.0",
		Created:     time.Now(),
		Creator: struct {
			Person string
			Tool   []string
		}{
			Person: defaultDocumentAuthor,
			Tool:   []string{"k8s.io/release/pkg/license"},
		},
	}
}

// AddPackage adds a new empty package to the document
func (d *Document) AddPackage(pkg *Package) error {
	if d.Packages == nil {
		d.Packages = map[string]*Package{}
	}

	if pkg.ID == "" {
		// If we so not have an ID but have a name generate it fro there
		reg := regexp.MustCompile("[^a-zA-Z0-9-]+")
		id := reg.ReplaceAllString(pkg.Name, "")
		if id != "" {
			pkg.ID = "SPDXRef-Package-" + id
		}
	}
	if pkg.ID == "" {
		return errors.New("package id is needed to add a new package")
	}
	if _, ok := d.Packages[pkg.ID]; ok {
		return errors.New("a package named " + pkg.ID + " already exists in the document")
	}

	d.Packages[pkg.ID] = pkg
	return nil
}

// AddFile adds a file
func (p *Package) AddFile(file *File) error {
	if p.Files == nil {
		p.Files = map[string]*File{}
	}
	// If file does not have an ID, we try to build one
	// by hashing the file name
	if file.ID == "" {
		if file.Name == "" {
			return errors.New("unable to generate file ID, filename not set")
		}
		if p.Name == "" {
			return errors.New("unable to generate file ID, filename not set")
		}
		h := sha1.New()
		if _, err := h.Write([]byte(p.Name + ":" + file.Name)); err != nil {
			return errors.Wrap(err, "getting sha1 of filename")
		}
		file.ID = "SPDXRef-File-" + fmt.Sprintf("%x", h.Sum(nil))
	}
	p.Files[file.ID] = file
	return nil
}

// AddPackage adds a new subpackage to a package
func (p *Package) AddPackage(pkg *Package) error {
	if p.Packages == nil {
		p.Packages = map[string]*Package{}
	}
	if pkg.ID == "" {
		// If we so not have an ID but have a name generate it fro there
		reg := regexp.MustCompile("[^a-zA-Z0-9-]+")
		id := reg.ReplaceAllString(pkg.Name, "")
		if id != "" {
			pkg.ID = "SPDXRef-Package-" + id
		}
	}
	if pkg.ID == "" {
		return errors.New("package name is needed to add a new package")
	}
	if _, ok := p.Packages[pkg.ID]; ok {
		return errors.New("a package named " + pkg.ID + " already exists in the document")
	}

	p.Packages[pkg.ID] = pkg
	return nil
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

// Render reders the spdx manifest
func (d *Document) Render() (doc string, err error) {
	var buf bytes.Buffer
	funcMap := template.FuncMap{
		// The name "title" is what the function will be called in the template text.
		"dateFormat": func(t time.Time) string { return "--- THIS DATE HAS TO BE FORMATTED ---" },
	}

	tmpl, err := template.New("document").Funcs(funcMap).Parse(docTemplate)
	if err != nil {
		log.Fatalf("parsing: %s", err)
	}

	// Run the template to verify the output.
	if err := tmpl.Execute(&buf, d); err != nil {
		return "", errors.Wrap(err, "executing spdx document template")
	}

	doc = buf.String()

	// Cycle all packages and get their data
	for _, pkg := range d.Packages {
		pkgDoc, err := pkg.Render()
		if err != nil {
			return "", errors.Wrap(err, "rendering pkg "+pkg.Name)
		}

		doc = doc + pkgDoc
		doc = doc + fmt.Sprintf("Relationship: %s DESCRIBES %s\n\n", d.ID, pkg.ID)
	}

	/*

		##### Package: hello-go-bin

		PackageName: hello-go-bin
		SPDXID: SPDXRef-Package-hello-go-bin
		PackageDownloadLocation: git@github.com:swinslow/spdx-examples.git#example6/content/build
		FilesAnalyzed: true
		PackageVerificationCode: 41acac4b846ee388cb6c1234f04489ccd5daa5a5
		PackageLicenseConcluded: GPL-3.0-or-later AND LicenseRef-Golang-BSD-plus-Patents
		PackageLicenseInfoFromFiles: NOASSERTION
		PackageLicenseDeclared: NOASSERTION
		PackageCopyrightText: NOASSERTION

		Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-hello-go-bin

		FileName: /hello
		SPDXID: SPDXRef-hello-go-binary
		FileChecksum: SHA1: 78ed46e8e6f86f19d3a6782979029be5f918235f
		FileChecksum: SHA256: 3d51cb6c9a38d437e8ee20a1902a15875ea1d3771a215622e14739532be14949
		FileChecksum: MD5: 9ec63d68bdceb2922548e3faa377e7d0
		LicenseConcluded: GPL-3.0-or-later AND LicenseRef-Golang-BSD-plus-Patents
		LicenseInfoInFile: NOASSERTION
		FileCopyrightText: NOASSERTION

		##### Relationships

		Relationship: SPDXRef-hello-go-binary GENERATED_FROM DocumentRef-hello-go-src:SPDXRef-hello-go-src
		Relationship: SPDXRef-hello-go-binary GENERATED_FROM DocumentRef-hello-go-src:SPDXRef-Makefile

		Relationship: DocumentRef-go-lib:SPDXRef-Package-go-compiler BUILD_TOOL_OF SPDXRef-Package-hello-go-bin

		Relationship: DocumentRef-go-lib:SPDXRef-Package-go.fmt RUNTIME_DEPENDENCY_OF SPDXRef-Package-hello-go-bin
		Relationship: DocumentRef-go-lib:SPDXRef-Package-go.fmt STATIC_LINK SPDXRef-Package-hello-go-bin

		Relationship: DocumentRef-go-lib:SPDXRef-Package-go.reflect STATIC_LINK SPDXRef-Package-hello-go-bin
		Relationship: DocumentRef-go-lib:SPDXRef-Package-go.strconv STATIC_LINK SPDXRef-Package-hello-go-bin
	*/
	return doc, err
}

// TODO: {{ if .ExternalDocumentRef }}ExternalDocumentRef:DocumentRef-hello-go-src https://swinslow.net/spdx-examples/example6/hello-go-src-v1 SHA256: 5aac40a3b28b4a0a571a327631d752ffda7d4631093b035f38bd201baa45565e{{ end -}}

// Render renders the document fragment of the package
func (p *Package) Render() (docFragment string, err error) {
	var buf bytes.Buffer
	tmpl, err := template.New("package").Parse(packageTemplate)
	if err != nil {
		return "", errors.Wrap(err, "parsing package template")
	}

	// If files were analyzed, calculate the verification
	if p.FilesAnalyzed {
		if len(p.Files) == 0 {
			return docFragment, errors.New("unable to get package verification code, package has no files")
		}
		shaList := []string{}
		for _, f := range p.Files {
			if f.Checksum == nil {
				return docFragment, errors.New("unable to render package, file has no checksums")
			}
			if _, ok := f.Checksum["SHA1"]; !ok {
				return docFragment, errors.New("unable to render package, files were analyzed but some do not have sha1 checksum")
			}
			shaList = append(shaList, f.Checksum["SHA1"])
		}
		sort.Strings(shaList)
		h := sha1.New()
		if h.Write([]byte(strings.Join(shaList, ""))); err != nil {
			return docFragment, errors.Wrap(err, "getting sha1 verficiation of files")
		}
		p.VerificationCode = fmt.Sprintf("%x", h.Sum(nil))
	}

	// Run the template to verify the output.
	if err := tmpl.Execute(&buf, p); err != nil {
		return "", errors.Wrap(err, "executing spdx package template")
	}

	docFragment = buf.String()

	for _, f := range p.Files {
		fileFragment, err := f.Render()
		if err != nil {
			return "", errors.Wrap(err, "rendering file "+f.Name)
		}
		docFragment = docFragment + fileFragment
		docFragment = docFragment + fmt.Sprintf("Relationship: %s CONTAINS %s\n\n", p.ID, f.ID)
	}

	// Print the contained sub packages
	if p.Packages != nil {
		for _, pkg := range p.Packages {
			pkgDoc, err := pkg.Render()
			if err != nil {
				return "", errors.Wrap(err, "rendering pkg "+pkg.Name)
			}

			docFragment = docFragment + pkgDoc
			docFragment = docFragment + fmt.Sprintf("Relationship: %s CONTAINS %s\n\n", p.ID, pkg.ID)
		}
	}
	return docFragment, nil
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
