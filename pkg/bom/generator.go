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

package bom

import (
	"archive/tar"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"k8s.io/release/pkg/license"
	"k8s.io/release/pkg/release"
	"k8s.io/release/pkg/spdx"
	"sigs.k8s.io/release-utils/hash"
	"sigs.k8s.io/release-utils/util"
)

const (
	commonLicensesRe           = `(?i)/usr/share/common-licenses/[-A-Z0-9\.]+`
	layerFileName              = "layer.tar"
	distrolessBundleURL        = "https://raw.githubusercontent.com/GoogleContainerTools/distroless/master/"
	distrolessBundle           = "package_bundle_amd64_debian10.versions"
	distrolessLicensePath      = "./usr/share/doc/"
	distrolessLicenseName      = "/copyright"
	distrolessCommonLicenseDir = "/usr/share/common-licenses/"

	goRunnerDownloadLocation = "https://github.com/kubernetes/release/tree/master/images/build/go-runner"
	goRunnerVersionURL       = "https://raw.githubusercontent.com/kubernetes/release/master/images/build/go-runner/VERSION"
	goRunnerLicenseURL       = "https://raw.githubusercontent.com/kubernetes/release/master/images/build/go-runner/Dockerfile"
)

// Generator is the abstraction for a bill of materials
type Generator struct {
	Options *Options
	ArtifactList
	impl generatorImplementation
}

func NewGenerator(opts *Options) (*Generator, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	gen := &Generator{
		Options: opts,
	}
	// gen.impl = &defaultGeneratorImplementation{}
	return gen, nil

}

// ArtifactList a list of artifacts to be added to the BOM
type ArtifactList struct {
	binaries []string // List of binaries to be analized
	images   []string // List of image tar files to be processed
}

// AddBinary adds a new naked binary to be written in the bom
func (list *ArtifactList) AddBinary(path string) error {
	if !util.Exists(path) {
		return errors.New("unable to add binary, specified path does not exist")
	}
	list.binaries = append(list.binaries, path)
	return nil
}

// AddImage adds a new image to the artifact list
func (list *ArtifactList) AddImage(path string) error {
	if !util.Exists(path) {
		return errors.New("unable to add layer, specified path does not exist")
	}
	if filepath.Ext(path) != ".tar" {
		return errors.New("image path has to point to a tar file")
	}
	logrus.Infof("Adding image to artifacts list %f", path)
	list.images = append(list.images, path)
	return nil
}

// Images returns the list of images
func (list *ArtifactList) Images() []string {
	return list.images
}

// Binaries returns the list of binaries registered
func (list *ArtifactList) Binaries() []string {
	return list.binaries
}

// Options stores the options for the bom generator
type Options struct {
	Name            string // Top level name for the document (Kubernetes)
	Version         string // Version of the software expressed in the BOM
	OutputFile      string // Path to output the BOM
	LicenseCacheDir string // Directory to cache SPDX licenses
}

// Validate checks if the options set is complete
func (o Options) Validate() error {
	// Implement
	return nil
}

//counterfeiter:generate . generatorImplementation
type generatorImplementation interface {
	createSPDXDocument(*Options) (*spdx.Document, error)
	generateImagePackage(string, *Options) (*spdx.Package, error)
	generateDistrolessPackage(string, *Options) (*spdx.Package, error)
	generateGoRunnerPackage(string, *Options) (*spdx.Package, error)
	generateContainerPackage(string, *Options) (*spdx.Package, error)
	fetchDistrolessPackages() (map[string]string, error)
	licenseReader(*Options) (*license.Reader, error)
}

type defaultGeneratorImplementation struct {
	reader *license.Reader
}

// generateSPDXBOM generates a spdx bill of materials
func (impl *defaultGeneratorImplementation) createSPDXDocument(o *Options) (
	doc *spdx.Document, err error,
) {
	// Create the BOM document to represent the image
	doc = spdx.NewDocument()
	doc.Name = o.Name
	doc.ID = "SPDXRef-DOCUMENT-" + o.Name
	doc.Creator.Tool = append(doc.Creator.Tool, "krel - The Kubernetes Release Toolbox")
	return doc, err
}

// Generate writes a Bill of Materials for the specified artifacts
func (g *Generator) Generate() (doc *spdx.Document, err error) {
	// Check options are correct before starting
	if err := g.Options.Validate(); err != nil {
		return doc, errors.Wrap(err, "checking bom generator options")
	}

	// Creatre the document to hold all packages
	doc, err = g.impl.createSPDXDocument(g.Options)
	if err != nil {
		return doc, errors.Wrap(err, "creating SPDX document")
	}

	// Cycle all images and add them to the document as SPDX Packages.
	// This assumes all images are built using the same
	// distroless-gorunner-container structure
	for _, imagePath := range g.Images() {
		pkg, err := g.generateImagePackage(imagePath)
		if err != nil {
			return doc, errors.Wrap(err, "generating SPDX package for "+imagePath)
		}
		if err := doc.AddPackage(pkg); err != nil {
			return doc, errors.Wrap(err, "adding image package to bom")
		}
	}

	return doc, err
}

func (g *Generator) generateImagePackage(tarPath string) (pkg *spdx.Package, err error) {
	return g.impl.generateImagePackage(tarPath, g.Options)
}

// ReadTarballManifest returns the manifest from a tar image
func ReadTarballManifest(tarPath string) (manifest ImageManifest, err error) {
	tarFile, err := os.Open(tarPath)
	if err != nil {
		return manifest, errors.Wrap(err, "reading tar file")
	}
	defer tarFile.Close()
	logrus.Infof("Extracting manifest from %s", tarFile.Name())

	tr := tar.NewReader(tarFile)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return manifest, errors.Wrap(err, "iterating over tar filefile filenames")
		}

		if hdr.FileInfo().Name() == "manifest.json" {

		}
	}
	return manifest, errors.New("unable to find image manifest")
}

// generateImagePackage gets a path to an image tarfile and returns a SPDX
//  package describing its layers. This code is written specific for the three layer
//  image structure produced by the Kubernetes release process.
func (impl *defaultGeneratorImplementation) generateImagePackage(
	tarPath string, o *Options) (pkg *spdx.Package, err error) {
	// Get the manifest from the tar file
	manifest, err := ReadTarballManifest(tarPath)
	if err != nil {
		return pkg, errors.Wrap(err, "getting image manifest from tar file")
	}

	// To proceed we need at least one tag in the manifestq
	if len(manifest.RepoTags) == 0 {
		return pkg, errors.New("image manifest does not include a repo tag")
	}

	// Get the repo tag to use a a download location
	// ie: k8s.gcr.io/kube-apiserver-arm:v1.20.4
	repotag := manifest.RepoTags[0]

	// And determine the image version from the tag
	tagparts := strings.Split(repotag, ":")
	if len(tagparts) < 2 {
		return pkg, errors.New("unable to get version from image repo tag")
	}

	// Create the top level package
	imagePackage := &spdx.Package{
		FilesAnalyzed:    true,
		Name:             strings.TrimPrefix(tagparts[0], release.GCRIOPathProd+"/"),
		DownloadLocation: repotag,
		Version:          tagparts[1],
	}

	// Extract the image layers
	tarfile, err := os.Open(tarPath)
	if err != nil {
		return pkg, errors.Wrap(err, "processing rarfile")
	}
	defer tarfile.Close()

	dir, err := os.MkdirTemp(os.TempDir(), "image-process-")
	if err != nil {
		return pkg, errors.Wrap(err, "creating temporary directory")
	}
	defer os.RemoveAll(dir)

	tr := tar.NewReader(tarfile)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return pkg, errors.Wrap(err, "reading the image tarfile")
		}
		if hdr.FileInfo().IsDir() {
			if err := os.MkdirAll(filepath.Join(dir, hdr.Name), os.FileMode(0o755)); err != nil {
				return pkg, errors.Wrap(err, "creating image directory structure")
			}
			continue
		}

		targetFile := filepath.Join(dir, hdr.Name)
		f, err := os.Create(targetFile)
		if err != nil {
			return pkg, errors.Wrap(err, "creating image layer file")
		}
		defer f.Close()

		if _, err := io.Copy(f, tr); err != nil {
			return pkg, errors.Wrap(err, "extracting image data")
		}
	}

	// Generate a base SPDX entry for each layer

	for _, layer := range manifest.LayerFiles {
		if !util.Exists(filepath.Join(dir, layer)) {
			return pkg, errors.Wrapf(err, "extracted layer not found: %s", layer)
		}

		sha256, err := hash.SHA256ForFile(filepath.Join(dir, layer))
		if err != nil {
			return nil, errors.Wrap(err, "get sha256")
		}

		sha512, err := hash.SHA512ForFile(filepath.Join(dir, layer))
		if err != nil {
			return nil, errors.Wrap(err, "get sha512")
		}

		fragment := &spdx.Package{
			Name:             layerFileName,
			ID:               "",
			DownloadLocation: goRunnerDownloadLocation,
			LicenseConcluded: "",
			FileName:         layer,
			Checksum: map[string]string{
				"SHA256": sha256,
				"SHA512": sha512,
			},
		}
		imagePackage.AddPackage(fragment)
	}

	/*

		// Cycle the layers in the image manifest
		for i, layer := range manifest.LayerFiles {
			if !util.Exists(filepath.Join(dir, layer)) {
				return pkg, errors.Wrapf(err, "extracted layer not found: %s", layer)
			}
			switch i {
			case 0:
				logrus.WithField("image", tagparts[0]).Infof("Processing layer #%d (distroless): %s", i, layer)
				fragment, err := impl.generateDistrolessPackage(filepath.Join(dir, layer), o)
				if err != nil {
					return pkg, errors.Wrap(err, "processing distroless layer")
				}
				fragment.FileName = "./" + layer
				imagePackage.AddPackage(fragment)
			case 1:
				logrus.WithField("image", tagparts[0]).Infof("Processing layer #%d (go-runner): %s", i, layer)
				fragment, err := impl.generateGoRunnerPackage(filepath.Join(dir, layer), o)
				if err != nil {
					return pkg, errors.Wrap(err, "processing go-runner layer")
				}
				fragment.FileName = "./" + layer
				imagePackage.AddPackage(fragment)
			case 2:
				logrus.WithField("image", tagparts[0]).Infof("Processing layer #%d (binary): %s", i, layer)
				fragment, err := impl.generateContainerPackage(filepath.Join(dir, layer), o)
				if err != nil {
					return pkg, errors.Wrap(err, "processing CCC layer")
				}
				fragment.FileName = "./" + layer
				imagePackage.AddPackage(fragment)
			}
		}
	*/

	/*

		// Cycle all files in the image to declare them in the BOM
		if err := filepath.Walk(dir,
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}

				// Try to generate more understandable IDs:
				spdxID := ""
				switch info.Name() {
				case "manifest.json":
					spdxID = "image-manifest"
				case "layer.tar":
					switch strings.TrimPrefix(path, dir+"/") {
					case manifest.LayerFiles[0]:
						spdxID = "distroless-layer"
					case manifest.LayerFiles[1]:
						spdxID = "go-runner-layer"
					case manifest.LayerFiles[2]:
						spdxID = "container-layer"
					}
				}
				if spdxID != "" {
					spdxID = "SPDXRef-File-" + imagePackage.Name + "-" + spdxID
				}

				file := &license.File{
					Name: "." + strings.TrimPrefix(path, dir),
					ID:   spdxID,
				}

				if err := file.ReadChecksums(path); err != nil {
					return errors.Wrap(err, "generating file checksums")
				}

				imagePackage.AddFile(file)
				return nil
			}); err != nil {
			return pkg, errors.Wrap(err, "reading image directory")
		}
	*/
	// Create the final SPDX package for the image:
	pkg = &spdx.Package{
		FilesAnalyzed: false, // sera true
		Name:          "binary",
		ID:            "SPDXRef-image",
		// DownloadLocation: goRunnerDownloadLocation,
		// FileName: tarPath, RepoTag?
	}
	pkg.Supplier.Person = "Kubernetes Release Managers (release-managers@kubernetes.io)"
	pkg.AddPackage(imagePackage)
	return pkg, nil
}

// generateGoRunnerPackage Reads and processes the go-runner layer
func (impl *defaultGeneratorImplementation) generateGoRunnerPackage(
	layerPath string, o *Options) (fragment *spdx.Package, err error) {
	fragment = &spdx.Package{
		FilesAnalyzed:    false,
		Name:             "go-runner",
		ID:               "SPDXRef-Package-go-runner",
		DownloadLocation: goRunnerDownloadLocation,
		FileName:         layerPath,
	}
	fragment.Supplier.Person = "Kubernetes Release Managers (release-managers@kubernetes.io)"
	/*
		licenseReader, err := impl.licenseReader(o)
		if err != nil {
			return fragment, errors.Wrap(err, "getting license reader to parse the go-runner image")
		}*/

	// Get the go-runner version
	// TODO: Add http retries
	ver, err := http.Get(goRunnerVersionURL)
	if err != nil {
		return fragment, errors.Wrap(err, "fetching go-runner VERSION file")
	}
	if ver.StatusCode < 200 || ver.StatusCode >= 399 {
		return fragment, errors.New("http error fetching go-runner version file")
	}
	versionb, err := ioutil.ReadAll(ver.Body)
	if err != nil {
		return fragment, errors.Wrap(err, "reading go-runner VERSION response")
	}
	logrus.Infof("go-runner image is at version %s", string(versionb))
	fragment.Version = string(versionb)

	// Read the docker file to scan for license
	lic, err := http.Get(goRunnerLicenseURL)
	if err != nil {
		return fragment, errors.Wrap(err, "fetching go-runner VERSION file")
	}
	if lic.StatusCode < 200 || lic.StatusCode >= 399 {
		return fragment, errors.New("http error fetching go-runner license URL")
	}

	df, err := ioutil.TempFile(os.TempDir(), "gorunner-dockerfile-")
	if err != nil {
		return fragment, errors.Wrap(err, "creating temporary file to read go-runner license")
	}
	defer df.Close()
	if _, err := io.Copy(df, lic.Body); err != nil {
		return fragment, errors.Wrap(err, "writing go-runner license to temp file")
	}

	// Let's extract the license for the layer:
	var grlic *license.License
	// First, check if the file has our boiler plate
	hasbp, err := license.HasKubernetesBoilerPlate(df.Name())
	if err != nil {
		return fragment, errors.Wrap(err, "checking for k8s boilerplate in go-runner")
	}
	// If the boilerplate was found, we know it is apache2
	if hasbp {
		//grlic = licenseReader.LicenseFromLabel("Apache-2.0")
		// Otherwise, as a fallback, try to classify the file
	} else {
		//grlic, err = licenseReader.LicenseFromFile(df.Name())
		if err != nil {
			return fragment, errors.Wrap(err, "attempting to read go-runner license")
		}
	}
	fragment.LicenseDeclared = grlic.LicenseID
	logrus.Infof("Found license %s in go-runner image", grlic.LicenseID)
	return fragment, nil
}

// fetchDistrolessPackages retrieves the package list published at the
//  distroless repository keyed by package name and version
func (impl *defaultGeneratorImplementation) fetchDistrolessPackages() (pkgInfo map[string]string, err error) {
	logrus.Info("Fetching distroless image package list")
	bundleResponse, err := http.Get(distrolessBundleURL + distrolessBundle)
	if err != nil {
		return nil, errors.Wrap(err, "fetching distroless image package manifest")
	}
	defer bundleResponse.Body.Close()
	body, err := io.ReadAll(bundleResponse.Body)
	if err != nil {
		return nil, errors.Wrap(err, "reading response from distroless packages")
	}

	pkgInfo = map[string]string{}
	json.Unmarshal(body, &pkgInfo)
	logrus.Infof("Distroless bundle for %s lists %d packages", distrolessBundle, len(pkgInfo))
	return pkgInfo, nil
}

// generateContainerPackage generates a SPDX package for the container layer
func (impl *defaultGeneratorImplementation) generateContainerPackage(
	tarPath string, o *Options) (fragment *spdx.Package, err error) {
	// Un tar the layer to register the files in the manifest
	logrus.Infof("Generating container package for %s", tarPath)
	tarfile, err := os.Open(tarPath)
	if err != nil {
		return fragment, errors.Wrap(err, "processing tar file")
	}
	defer tarfile.Close()

	dir, err := os.MkdirTemp(os.TempDir(), "image-process-container-")
	if err != nil {
		return fragment, errors.Wrap(err, "creating temporary directory")
	}
	defer os.RemoveAll(dir)

	fragment = &spdx.Package{
		FilesAnalyzed: false, // sera true
		Name:          "binary",
		ID:            "SPDXRef-Package-single-binary",
		// DownloadLocation: goRunnerDownloadLocation,
		FileName: tarPath,
	}
	fragment.Supplier.Person = "Kubernetes Release Managers (release-managers@kubernetes.io)"

	tr := tar.NewReader(tarfile)
	numFiles := 0
	lastFile := ""
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return fragment, errors.Wrap(err, "reading the image tarfile")
		}

		if hdr.FileInfo().IsDir() {
			continue
		}

		if strings.HasPrefix(filepath.Base(hdr.FileInfo().Name()), ".wh") {
			logrus.Info("Skipping extraction of whiteout file")
			continue
		}

		if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(hdr.Name)), os.FileMode(0o755)); err != nil {
			return fragment, errors.Wrap(err, "creating image directory structure")
		}

		targetFile := filepath.Join(dir, hdr.Name)
		f, err := os.Create(targetFile)
		if err != nil {
			return fragment, errors.Wrap(err, "creating image layer file")
		}
		defer f.Close()

		if _, err := io.Copy(f, tr); err != nil {
			return fragment, errors.Wrap(err, "extracting image data")
		}
		lastFile = hdr.Name
		numFiles++
	}

	if numFiles == 1 {
		logrus.Info("Single binary found in layer: " + lastFile)
	}

	return fragment, err
}

type ImageManifest struct {
	ConfigFilename string   `json:"Config"`
	RepoTags       []string `json:"RepoTags"`
	LayerFiles     []string `json:"Layers"`
}
