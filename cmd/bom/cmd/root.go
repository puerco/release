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

package cmd

import (
	"fmt"

	"github.com/pkg/errors"
	"k8s.io/release/pkg/spdx"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/log"
)

var rootCmd = &cobra.Command{
	Short: "bom: A tool for working with SPDX manifests",
	Long: `bom (Bill of Materials)

bom is a little utility that lets software authors generate
SPDX manifests to describe the contents of a release. The
SPDX manifests provide a way to list and verify all items
contained in packages, images, and individual files while
packing the data along with licensing information.

bom is still in its early stages and it is an effort to open
the libraries developed for the Kubernetes SBOM for other 
projects to use.

`,
	Use:          "bom",
	SilenceUsage: false,
	// SilenceErrors:     true,
	PersistentPreRunE: initLogging,
}

var generateCmd = &cobra.Command{
	Short: "bom generate → Create SPDX manifests",
	Long: `bom → Create SPDX manifests

generate is the bom subcommand to generate SPDX manifests.
Currently supports creating SBOM for files, images, and docker
archives (images in tarballs). Supports remote pulling from
registries.

`,
	Use:               "generate",
	SilenceUsage:      true,
	SilenceErrors:     true,
	PersistentPreRunE: initLogging,
	RunE: func(cmd *cobra.Command, args []string) error {
		return generateBOM(genOpts)
	},
}

type commandLineOptions struct {
	logLevel string
}

type generateOptions struct {
	analyze    bool
	namespace  string
	outputFile string
	images     []string
	tarballs   []string
	files      []string
}

// Validate verify options consistency
func (opts *generateOptions) Validate() error {
	if len(opts.images) == 0 && len(opts.files) == 0 && len(opts.tarballs) == 0 {
		return errors.New("to generate a SPDX BOM you have to provide at least one image or file")
	}
	return nil
}

var (
	commandLineOpts = &commandLineOptions{}
	genOpts         = &generateOptions{}
)

func init() {
	generateCmd.PersistentFlags().StringSliceVarP(
		&genOpts.images,
		"image",
		"i",
		[]string{},
		"list of images",
	)
	generateCmd.PersistentFlags().StringSliceVarP(
		&genOpts.files,
		"file",
		"f",
		[]string{},
		"list of files to include",
	)

	generateCmd.PersistentFlags().StringSliceVarP(
		&genOpts.tarballs,
		"tarball",
		"t",
		[]string{},
		"list of docker archive tarballs to include in the manifest",
	)

	generateCmd.PersistentFlags().StringVarP(
		&genOpts.namespace,
		"namespace",
		"n",
		"",
		"an URI that servers as namespace for the SPDX doc",
	)

	generateCmd.PersistentFlags().StringVarP(
		&genOpts.outputFile,
		"output",
		"o",
		"",
		"path to the file where the document will be written (defaults to STDOUT)",
	)

	generateCmd.PersistentFlags().BoolVarP(
		&genOpts.analyze,
		"analyze-images",
		"a",
		false,
		"perform deep image analysis",
	)

	rootCmd.PersistentFlags().StringVar(
		&commandLineOpts.logLevel,
		"log-level",
		"info",
		fmt.Sprintf("the logging verbosity, either %s", log.LevelNames()),
	)

	rootCmd.AddCommand(generateCmd)
}

// Execute builds the command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(err)
	}
}

func initLogging(*cobra.Command, []string) error {
	return log.SetupGlobalLogger(commandLineOpts.logLevel)
}

func generateBOM(opts *generateOptions) error {
	if err := opts.Validate(); err != nil {
		return errors.Wrap(err, "validating command line options")
	}
	logrus.Info("Generating SPDX Bill of Materials")

	if opts.namespace == "" {
		logrus.Warn("Document namespace is empty, a mock URI will be supplied but the doc will not be valid")
		opts.namespace = "http://example.com/"
	}

	builder := spdx.NewDocBuilder()
	doc, err := builder.Generate(&spdx.DocGenerateOptions{
		Tarballs:      opts.tarballs,
		Files:         opts.files,
		Images:        opts.images,
		OutputFile:    opts.outputFile,
		Namespace:     "",
		AnalyseLayers: opts.analyze,
	})
	if err != nil {
		return errors.Wrap(err, "generating doc")
	}

	if opts.outputFile == "" {
		markup, err := doc.Render()
		if err != nil {
			return errors.Wrap(err, "rendering document")
		}
		fmt.Println(markup)
	}
	return nil
}
