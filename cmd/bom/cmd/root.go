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
	Short: "bom → A tool for working with SPDX manifests",
	Long: `bom → A tool  for working with SPDX manifests

`,
	Use:          "bom",
	SilenceUsage: false,
	//SilenceErrors:     true,
	PersistentPreRunE: initLogging,
}

var generateCmd = &cobra.Command{
	Short: "bom generate → Create SPDX manifests",
	Long: `bom → Create SPDX manifests

bom allows software creators to generate SPDX manifests from
container images and binaries

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

var commandLineOpts = &commandLineOptions{}
var genOpts = &generateOptions{}

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
		Tarballs:   opts.tarballs,
		Files:      opts.files,
		Images:     opts.images,
		OutputFile: opts.outputFile,
		Namespace:  "",
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
