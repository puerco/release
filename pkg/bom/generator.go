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
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"k8s.io/release/pkg/license"
	"k8s.io/release/pkg/release"
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
	Options   *Options
	Artifacts *ArtifactList
	generatorImplementation
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
	if filepath.Ext(path) != "tar" {
		return errors.New("image path has to point to a tar file")
	}
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
	createSPDXDocument(*Options) (*license.Document, error)
	generateImagePackage(string, *Options) (*license.Package, error)
	generateDistrolessPackage(string, *Options) (*license.Package, error)
	generateGoRunnerPackage(string, *Options) (*license.Package, error)
	generateContainerPackage(string, *Options) (*license.Package, error)
	fetchDistrolessPackages(map[string]string, error)
	licenseReader(*Options) *license.Reader
}

type defaultGeneratorImplementation struct {
	reader *license.Reader
}

// generateSPDXBOM generates a spdx bill of materials
func (impl *defaultGeneratorImplementation) createSPDXDocument(
	o *Options) (doc *license.Document, err error,
) {
	// Create a new SPDX to build the document
	spdx, err := license.NewSPDX()
	if err != nil {
		logrus.Fatal(err)
	}

	// Create the BOM document to represent the image
	doc = spdx.NewDocument()
	doc.Name = o.Name
	doc.ID = "SPDXRef-DOCUMENT-" + o.Name
	doc.Creator.Tool = append(doc.Creator.Tool, "krel - The Kubernetes Release Toolbox")
	return doc, err
}

// Generate writes a Bill of Materials for the specified artifacts
func (g *Generator) Generate() (doc *license.Document, err error) {
	// Check options are correct before starting
	if err := g.Options.Validate(); err != nil {
		return doc, errors.Wrap(err, "checking bom generator options")
	}

	// Creatre the document to hold all packages
	doc, err = g.generatorImplementation.createSPDXDocument(g.Options)
	if err != nil {
		return doc, errors.Wrap(err, "creating SPDX document")
	}

	// Cycle all images and add them to the document as SPDX Packages.
	// This assumes all images are built using the same
	// distroless-gorunner-container structure
	for _, imagePath := range g.Artifacts.Images() {
		pkg, err := g.generateImagePackage(imagePath)
		if err != nil {
			return doc, errors.Wrap(err, "generating SPDX package for")
		}
		if err := doc.AddPackage(pkg); err != nil {
			return doc, errors.Wrap(err, "adding image package to bom")
		}
	}

	return doc, err
}

func (g *Generator) generateImagePackage(tarPath string) (pkg *license.Package, err error) {
	return g.generatorImplementation.generateImagePackage(tarPath, g.Options)
}

// generateImagePackage gets a path to an image tarfile and returns a SPDX
//  package describing its layers. This code is written specific for the three layer
//  image structure produced by the Kubernetes release process.
func (impl *defaultGeneratorImplementation) generateImagePackage(
	tarPath string, o *Options) (pkg *license.Package, err error) {
	// Get the manifest from the tar file
	manifest, err := release.GetTarManifest(tarPath)
	if err != nil {
		return pkg, errors.Wrap(err, "getting image manifest from tar file")
	}

	// To proceed we need at least one tag in the manifest
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

	imagePackage := &license.Package{
		FilesAnalyzed:    true,
		Name:             strings.TrimPrefix(tagparts[0], release.GCRIOPathProd+"/"),
		DownloadLocation: repotag,
		Version:          tagparts[1],
		/*
			FileName:         layerFileName,
			Supplier: struct {
				Person       string
				Organization string
			}{},
			Originator: struct {
				Person       string
				Organization string
			}{},
			Packages: map[string]*license.Package{},
			Files:    map[string]*license.File{},
		*/
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
	// Cycle the layers in the image manifest
	for i, layer := range manifest.Layers {
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
			imagePackage.AddPackage(&fragment)
		case 1:
			logrus.WithField("image", tagparts[0]).Infof("Processing layer #%d (go-runner): %s", i, layer)
			fragment, err := impl.generateGoRunnerPackage(filepath.Join(dir, layer), o)
			if err != nil {
				return pkg, errors.Wrap(err, "processing go-runner layer")
			}
			fragment.FileName = "./" + layer
			imagePackage.AddPackage(&fragment)
		case 2:
			logrus.WithField("image", tagparts[0]).Infof("Processing layer #%d (binary): %s", i, layer)
			fragment, err := impl.generateContainerPackage(filepath.Join(dir, layer), o)
		}
	}

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
				case manifest.Layers[0]:
					spdxID = "distroless-layer"
				case manifest.Layers[1]:
					spdxID = "go-runner-layer"
				case manifest.Layers[2]:
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

	pkg.AddPackage(imagePackage)
	return pkg, nil
}

// GenerateDistrolessFragment reads the distroless image layer and produces a
// spdx document fragment
func (impl defaultGeneratorImplementation) generateDistrolessPackage(
	layerPath string, o *Options) (pkg license.Package, err error) {
	// Create a new license reader to scan license files
	licenseReader, err := impl.licenseReader(o)
	if err != nil {
		return pkg, errors.Wrap(err, "creating license reader to scan distroless image")
	}

	// Create the package representing the distroless layer
	pkg = license.Package{
		Name:          "distroless",
		ID:            "SPDXRef-Package-distroless",
		FilesAnalyzed: false,
	}

	// Fetch the current distrolless packages
	packageList, err := impl.fetchDistrolessPackages()
	if err != nil {
		return pkg, errors.Wrap(err, "getting package lists")
	}

	// Open the distroless layer tar for reading
	tarfile, err := os.Open(layerPath)
	if err != nil {
		return pkg, errors.Wrap(err, "opening distroless image layer ")
	}
	defer tarfile.Close()
	dir, err := os.MkdirTemp(os.TempDir(), "image-process-")
	if err != nil {
		return pkg, errors.Wrap(err, "creating temporary directory")
	}
	// defer os.RemoveAll(dir)
	tr := tar.NewReader(tarfile)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return pkg, errors.Wrap(err, "reading the image tarfile")
		}

		// Scan the license directories to to determine the installed packages
		if strings.HasPrefix(hdr.Name, distrolessLicensePath) && strings.HasSuffix(hdr.Name, distrolessLicenseName) {
			// We infer the name of the package from the license directory
			packageName := strings.TrimSuffix(strings.TrimPrefix(hdr.Name, distrolessLicensePath), distrolessLicenseName)
			logrus.Infof("Creating SPDX subpackage " + packageName)
			subpkg := &license.Package{Name: packageName}
			if _, ok := packageList[subpkg.Name]; ok {
				logrus.Infof("distroless includes version %s of %s", packageList[subpkg.Name], subpkg.Name)
				subpkg.Version = packageList[subpkg.Name]
			} else {
				logrus.Warnf("could not determine version for package", packageList[subpkg.Name], subpkg.Name)
			}

			// Extract the package license to a file
			f, err := os.Create(filepath.Join(dir, packageName+".license"))
			if err != nil {
				return pkg, errors.Wrap(err, "creating image layer file")
			}
			defer f.Close()

			if _, err := io.Copy(f, tr); err != nil {
				return pkg, errors.Wrap(err, "extracting license data for "+subpkg.Name)
			}

			// Use our license classifier to try to determine
			// the license we are dealing with
			spdxlicense, err := licenseReader.LicenseFromFile(f.Name())
			if err != nil {
				return pkg, errors.Wrap(err, "reading license from file")
			}

			// If we still do not have a license, try to get it from the
			// devian copyright files. We have to read the files so...
			if spdxlicense == nil {
				// ...open the file
				fileData, err := ioutil.ReadFile(filepath.Join(dir, packageName+".license"))
				if err != nil {
					return pkg, errors.Wrap(err, "reading license file")
				}

				// We will try to look for the license in two ways:
				if strings.Contains(string(fileData), "is in the public domain") {
					// Option 1: File is in the public domain
					logrus.Info("File is the public domain")

					// In this case we include the full license text in the manifest
					subpkg.CopyrightText = string(fileData)
					subpkg.LicenseComments = "Found public domain declaration in copyright text file"

				} else {

					// Option 2: Copyright file references an installed license.
					re := regexp.MustCompile(commonLicensesRe)
					label := re.FindString(string(fileData))
					label = strings.TrimPrefix(label, distrolessCommonLicenseDir)
					label = strings.TrimSuffix(label, ".")

					// Translate from debian to SPDX label
					label = license.DebianLicenseLabels[label]
					if label != "" {
						spdxlicense = licenseReader.LicenseFromLabel(label)
						logrus.Infof("Found license %s for package %s by reading copyright file", spdxlicense.LicenseID, subpkg.Name)
						subpkg.LicenseDeclared = spdxlicense.LicenseID
					}
				}
			} else {
				subpkg.LicenseDeclared = spdxlicense.LicenseID
			}

			// Add the debian package to the layer package
			if err := pkg.AddPackage(subpkg); err != nil {
				return pkg, errors.Wrapf(err, "adding %s subpackage", subpkg.Name)
			}

		}
	}
	return pkg, nil
}

// generateGoRunnerPackage Reads and processes the go-runner layer
func (impl *defaultGeneratorImplementation) generateGoRunnerPackage(
	layerPath string, o *Options) (fragment license.Package, err error) {
	fragment = license.Package{
		FilesAnalyzed:    false,
		Name:             "go-runner",
		ID:               "SPDXRef-Package-go-runner",
		DownloadLocation: goRunnerDownloadLocation,
		FileName:         layerPath,
	}
	fragment.Supplier.Person = "Kubernetes Release Managers (release-managers@kubernetes.io)"

	licenseReader, err := impl.licenseReader(o)
	if err != nil {
		return fragment, errors.Wrap(err, "getting license reader to parse the go-runner image")
	}

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
	defer df.Close()
	if err != nil {
		return fragment, errors.Wrap(err, "creating temporary file to read go-runner license")
	}
	if _, err := io.Copy(df, lic.Body); err != nil {
		return fragment, errors.Wrap(err, "writing go-runner license to temp file")
	}

	// Let's extract the license for the layer:
	var grlic *license.SPDXLicense
	// First, check if the file has our boiler plate
	hasbp, err := license.HasKubernetesBoilerPlate(df.Name())
	if err != nil {
		return fragment, errors.Wrap(err, "checking for k8s boilerplate in go-runner")
	}
	// If the boilerplate was found, we know it is apache2
	if hasbp {
		grlic = licenseReader.LicenseFromLabel("Apache-2.0")
		// Otherwise, as a fallback, try to classify the file
	} else {
		grlic, err = licenseReader.LicenseFromFile(df.Name())
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

// licenseReader returns a reusable license reader
func (impl *defaultGeneratorImplementation) licenseReader(o *Options) (*license.Reader, error) {
	if impl.reader == nil {
		// We use a defualt license cache
		opts := license.DefaultReaderOptions
		ldir := filepath.Join(os.TempDir(), "spdx-license-reader-licenses")
		// ... unless overriden by the options
		if o.LicenseCacheDir != "" {
			ldir = o.LicenseCacheDir
		}

		// If the license cache does not exist, create it
		if !util.Exists(ldir) {
			if err := os.Mkdir(ldir, os.FileMode(0o0755)); err != nil {
				return nil, errors.Wrap(err, "Failed to create license cache directory")
			}
		}
		opts.CacheDir = ldir
		// Create the new reader
		reader, err := license.NewReaderWithOptions(opts)
		if err != nil {
			return nil, errors.Wrap(err, "creating reusable license reader")
		}
		impl.reader = reader
	}
	return impl.reader, nil
}

// generateContainerPackage generates a SPDX package for the container layer
func (impl *defaultGeneratorImplementation) generateContainerPackage(
	tarPath string, o *Options) (pkg *license.Package, err error) {
	// Un tar the layer to register the files in the manifest
	tarfile, err := os.Open(tarPath)
	if err != nil {
		return pkg, errors.Wrap(err, "processing tar file")
	}
	defer tarfile.Close()

	dir, err := os.MkdirTemp(os.TempDir(), "image-process-container-")
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

	return pkg, err
}
