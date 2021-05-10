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

package spdx

import (
	"archive/tar"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"

	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"k8s.io/release/pkg/license"
	"sigs.k8s.io/release-utils/http"
	"sigs.k8s.io/release-utils/util"
)

const (
	defaultDocumentAuthor      = "Kubernetes Release Managers (release-managers@kubernetes.io)"
	archiveManifestFilename    = "manifest.json"
	distrolessBundleURL        = "https://raw.githubusercontent.com/GoogleContainerTools/distroless/master/"
	distrolessBundle           = "package_bundle_amd64_debian10.versions" // TODO: Perhaps make an option
	distrolessLicensePath      = "./usr/share/doc/"
	distrolessLicenseName      = "/copyright"
	distrolessCommonLicenseDir = "/usr/share/common-licenses/"
	commonLicensesRe           = `(?i)/usr/share/common-licenses/[-A-Z0-9\.]+`
)

type SPDX struct {
	impl    spdxImplementation
	options *Options
}

func NewSPDX() *SPDX {
	return &SPDX{
		impl:    &spdxDefaultImplementation{},
		options: &defaultSPDXOptions,
	}
}

type Options struct {
	LicenseCacheDir string // Directory to cache SPDX license information
}

var defaultSPDXOptions = Options{}

type archiveManifest struct {
	ConfigFilename string   `json:"Config"`
	RepoTags       []string `json:"RepoTags"`
	LayerFiles     []string `json:"Layers"`
}

func readArchiveManifest(manifestPath string) (manifest *archiveManifest, err error) {
	// Check that we have the archive manifest.json file
	if !util.Exists(manifestPath) {
		return manifest, errors.New("unable to find manifest file " + manifestPath)
	}

	// Parse the json file
	manifestData := []archiveManifest{}
	manifestJson, err := os.ReadFile(manifestPath)
	if err != nil {
		return manifest, errors.Wrap(err, "unable to read from tarfile")
	}
	if err := json.Unmarshal(manifestJson, &manifestData); err != nil {
		fmt.Println(string(manifestJson))
		return manifest, errors.Wrap(err, "unmarshalling image manifest")
	}
	return &manifestData[0], nil
}

// PackageFromImageTarball returns a SPDX package from a tarball
func (spdx *SPDX) PackageFromImageTarball(tarPath string) (imagePackage *Package, err error) {
	logrus.Infof("Generating SPDX package from image tarball %s", tarPath)

	// Extract all files from tarfile
	dir, err := spdx.ExtractTarballTmp(tarPath)
	if err != nil {
		return nil, errors.Wrap(err, "extracting tarball to temp dir")
	}
	defer os.RemoveAll(dir)

	// Read the archive manifest json:
	manifest, err := readArchiveManifest(
		filepath.Join(dir, archiveManifestFilename),
	)
	if err != nil {
		return nil, errors.Wrap(err, "while reading docker archive manifest")
	}

	if len(manifest.RepoTags[0]) == 0 {
		return nil, errors.Wrap(
			err, "unable to add tar archive, manifest does not have a RepoTags entry",
		)
	}

	logrus.Infof("Package describes %s image", manifest.RepoTags[0])

	// Create the new SPDX package
	imagePackage = NewPackage()
	imagePackage.Options().WorkDir = dir
	// imagePackage.FilesAnalyzed = true
	imagePackage.Name = manifest.RepoTags[0]

	// Cycle all the layers from the manifest and add them as packages
	for _, layerFile := range manifest.LayerFiles {
		pkg := NewPackage()
		pkg.options.WorkDir = dir
		pkg.ReadSourceFile(filepath.Join(dir, layerFile))
		// Build the pkg name from its internal path
		h := sha1.New()
		if h.Write([]byte(layerFile)); err != nil {
			return nil, errors.Wrap(err, "hashing file path")
		}
		pkg.Name = fmt.Sprintf("%x", h.Sum(nil))
		// pkg.Name = filepath.Dir(layerFile)
		if err := imagePackage.AddPackage(pkg); err != nil {
			return nil, errors.Wrap(err, "adding layer to image package")
		}
	}

	// return the finished package
	return imagePackage, nil
}

// containerLayerHandler is an interface that knows how to read a
// known container layer and populate a SPDX package
type containerLayerHandler interface {
	func readPackageData(layerPath string, pkg *Package, )
}

func (spdx *SPDX) HandleLayer(layerPath string, pkg *Package, handler containerLayerHandler) error {

}

// ExtractTarballTmp extracts a tarball to a temp file
func (spdx *SPDX) ExtractTarballTmp(tarPath string) (tmpDir string, err error) {
	tmpDir, err = os.MkdirTemp(os.TempDir(), "spdx-tar-extract-")
	if err != nil {
		return tmpDir, errors.Wrap(err, "creating temporary directory for tar extraction")
	}

	// Open the tar file
	f, err := os.Open(tarPath)
	if err != nil {
		return tmpDir, errors.Wrap(err, "opening tarball")
	}

	tr := tar.NewReader(f)
	numFiles := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return tmpDir, errors.Wrap(err, "reading the image tarfile")
		}

		if hdr.FileInfo().IsDir() {
			continue
		}

		if strings.HasPrefix(filepath.Base(hdr.FileInfo().Name()), ".wh") {
			logrus.Info("Skipping extraction of whiteout file")
			continue
		}

		if err := os.MkdirAll(
			filepath.Join(tmpDir, filepath.Dir(hdr.Name)), os.FileMode(0o755),
		); err != nil {
			return tmpDir, errors.Wrap(err, "creating image directory structure")
		}

		targetFile := filepath.Join(tmpDir, hdr.Name)
		f, err := os.Create(targetFile)
		if err != nil {
			return tmpDir, errors.Wrap(err, "creating image layer file")
		}
		defer f.Close()

		if _, err := io.Copy(f, tr); err != nil {
			return tmpDir, errors.Wrap(err, "extracting image data")
		}
		numFiles++
	}
	logrus.Infof("Successfully extracted %d files from image tarball %s", numFiles, tarPath)
	return tmpDir, err
}

// PullImagesToArchive
func PullImagesToArchive(reference, path string) error {
	ref, err := name.ParseReference(reference)
	if err != nil {
		return errors.Wrapf(err, "parsing reference %q", reference)
	}

	img, err := remote.Image(ref)
	if err != nil {
		return errors.Wrap(err, "getting image")
	}

	// WriteToFile wants a tag to write to the tarball, but we might have
	// been given a digest.
	// If the original ref was a tag, use that. Otherwise, if it was a
	// digest, tag the image with :i-was-a-digest instead.
	tag, ok := ref.(name.Tag)
	if !ok {
		d, ok := ref.(name.Digest)
		if !ok {
			return fmt.Errorf("ref wasn't a tag or digest")
		}
		tag = d.Repository.Tag("from-digest") // FIXME: Digest?
	}

	// no progress channel (for now)
	return tarball.MultiWriteToFile(path, map[name.Tag]v1.Image{tag: img})
}

type spdxImplementation interface {
	readDistrolessLayer(string, *Package, *Options) error
	fetchDistrolessPackages() (map[string]string, error)
	licenseReader(*Options) (*license.Reader, error)
}

type spdxDefaultImplementation struct {
	reader *license.Reader
}

// GenerateDistrolessFragment reads the distroless image layer and produces a
// spdx document fragment
func (di *spdxDefaultImplementation) readDistrolessLayer(layerPath string, pkg *Package, o *Options) (err error) {
	// Create a new license reader to scan license files
	licenseReader, err := di.licenseReader(o)
	if err != nil {
		return errors.Wrap(
			err, "creating license reader to scan distroless image",
		)
	}

	// Create the package representing the distroless layer
	pkg.Name = "distroless"
	pkg.ID = "SPDXRef-Package-distroless"
	pkg.FilesAnalyzed = false

	// Fetch the current distrolless package list
	packageList, err := di.fetchDistrolessPackages()
	if err != nil {
		return errors.Wrap(err, "getting package lists")
	}

	// Open the distroless layer tar for reading
	tarfile, err := os.Open(layerPath)
	if err != nil {
		return errors.Wrap(err, "opening distroless image layer ")
	}
	defer tarfile.Close()
	dir, err := os.MkdirTemp(os.TempDir(), "image-process-")
	if err != nil {
		return errors.Wrap(err, "creating temporary directory")
	}
	// defer os.RemoveAll(dir)
	tr := tar.NewReader(tarfile)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "reading the image tarfile")
		}

		// Scan the license directories to to determine the installed packages
		if strings.HasPrefix(hdr.Name, distrolessLicensePath) && strings.HasSuffix(hdr.Name, distrolessLicenseName) {
			// We infer the name of the package from the license directory
			packageName := strings.TrimSuffix(strings.TrimPrefix(hdr.Name, distrolessLicensePath), distrolessLicenseName)
			logrus.Infof("Creating SPDX subpackage " + packageName)
			subpkg := NewPackage()
			subpkg.Name = packageName
			if _, ok := packageList[subpkg.Name]; ok {
				logrus.Infof("distroless includes version %s of %s", packageList[subpkg.Name], subpkg.Name)
				subpkg.Version = packageList[subpkg.Name]
			} else {
				logrus.Warnf("could not determine version for package", packageList[subpkg.Name], subpkg.Name)
			}

			// Extract the package license to a file
			f, err := os.Create(filepath.Join(dir, packageName+".license"))
			if err != nil {
				return errors.Wrap(err, "creating image layer file")
			}
			defer f.Close()

			if _, err := io.Copy(f, tr); err != nil {
				return errors.Wrap(err, "extracting license data for "+subpkg.Name)
			}

			// Use our license classifier to try to determine
			// the license we are dealing with
			spdxlicense, err := licenseReader.LicenseFromFile(f.Name())
			if err != nil {
				return errors.Wrap(err, "reading license from file")
			}

			// If we still do not have a license, try to get it from the
			// devian copyright files. We have to read the files so...
			if spdxlicense == nil {
				// ...open the file
				fileData, err := ioutil.ReadFile(filepath.Join(dir, packageName+".license"))
				if err != nil {
					return errors.Wrap(err, "reading license file")
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
				return errors.Wrapf(err, "adding %s subpackage", subpkg.Name)
			}

		}
	}
	return nil
}

// fetchDistrolessPackages retrieves the package list published at the
//  distroless repository keyed by package name and version
func (di *spdxDefaultImplementation) fetchDistrolessPackages() (pkgInfo map[string]string, err error) {
	logrus.Info("Fetching distroless image package list")
	body, err := http.NewAgent().Get(distrolessBundleURL + distrolessBundle)
	if err != nil {
		return nil, errors.Wrap(err, "fetching distroless image package manifest")
	}

	pkgInfo = map[string]string{}
	json.Unmarshal(body, &pkgInfo)
	logrus.Infof(
		"Distroless bundle for %s lists %d packages",
		distrolessBundle, len(pkgInfo),
	)
	return pkgInfo, nil
}

// licenseReader returns a reusable license reader
func (di *spdxDefaultImplementation) licenseReader(o *Options) (*license.Reader, error) {
	if di.reader == nil {
		logrus.Info("Initializing licence reader with default options")
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
				return nil, errors.Wrap(err, "creating license cache directory")
			}
		}
		opts.CacheDir = ldir
		// Create the new reader
		reader, err := license.NewReaderWithOptions(opts)
		if err != nil {
			return nil, errors.Wrap(err, "creating reusable license reader")
		}
		di.reader = reader
	}
	return di.reader, nil
}
