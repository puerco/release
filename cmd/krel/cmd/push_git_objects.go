/*
Copyright 2020 The Kubernetes Authors.

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
	"strings"

	"github.com/pkg/errors"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"k8s.io/release/pkg/git"
	"k8s.io/release/pkg/util"
)

// pushGitObjectsCmd is the krel push-git-objects subcommand
var pushGitObjectsCmd = &cobra.Command{
	Use:   "push-git-objects",
	Short: "DESC",
	Long: `krel push-git-objects

TBD
`,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := runPushGitObjects(pushGitObjectsOpts)
		if err != nil {
			return err
		}
		return nil
	},
}

type pushGitObjectsOptions struct {
	branch       string
	parentBranch string
	buildVersion string
	dryRun       bool
	sayYes       bool
	releaseTypes []string
}

var pushGitObjectsOpts = &pushGitObjectsOptions{}

func init() {
	pushGitObjectsCmd.PersistentFlags().StringVar(
		&pushGitObjectsOpts.branch,
		"branch",
		"",
		"branch name to push",
	)

	pushGitObjectsCmd.PersistentFlags().StringVar(
		&pushGitObjectsOpts.parentBranch,
		"parent-branch",
		git.DefaultBranch,
		"parent branch", // ???
	)

	pushGitObjectsCmd.PersistentFlags().StringVar(
		&pushGitObjectsOpts.buildVersion,
		"build-version",
		"",
		"build version to be used",
	)

	pushGitObjectsCmd.PersistentFlags().BoolVarP(
		&pushGitObjectsOpts.sayYes,
		"yes",
		"y",
		false,
		"say yes to prompts without asking the user",
	)

	pushGitObjectsCmd.PersistentFlags().StringSliceVar(
		&pushGitObjectsOpts.releaseTypes,
		"release-types",
		[]string{},
		"a list of relese types (offcial, alpha, beta, rc)",
	)

	rootCmd.AddCommand(pushGitObjectsCmd)
}

func runPushGitObjects(options *pushGitObjectsOptions) (err error) {
	// The real deal?
	dryRunFlag := " --dry-run"
	if rootOpts.nomock {
		dryRunFlag = ""
	}

	if !options.sayYes {
		_, success, err := util.Ask(
			fmt.Sprintf("Pausing here. Confirm push%s of tags and bits", dryRunFlag),
			"|y:Y:yes|", 0,
		)
		if err != nil {
			return errors.Wrap(err, "asking the user to confirm push")
		}
		if !success {
			logrus.Info("Exiting...")
			return errors.New("git object push cancelled by user")
		}
	}

	logrus.Info("Checkout master branch to push objects:")
	// TODO: Perhaps verify that we are running on k/k ?
	repo, err := git.OpenRepo(rootOpts.repoPath)
	if err != nil {
		return errors.Wrap(err, "opening repo")
	}

	// Set the dry run property when running in mock
	if !rootOpts.nomock {
		repo.SetDry()
	}

	if err := repo.Checkout(git.DefaultBranch); err != nil {
		return errors.Wrapf(err, "checking out %s branch", git.DefaultBranch)
	}

	logrus.Infof("Pushing%s tags", dryRunFlag)
	for _, releaseType := range options.releaseTypes {
		tag := fmt.Sprintf("-%s", releaseType) // FIXME fmtp.Sprintf  ← ${RELEASE_VERSION[$release_type]} eg RELEASE_VERSION[rc]="v1.19.0-rc.0"
		logrus.Info("Pushing %s tag: ", tag)
		if err := repo.PushWithReties(tag, 10); err != nil {
			return errors.Wrapf(err, "pushing tag %s", tag)
		}
	}

	// if a release branch was specified, push it
	if strings.HasPrefix(options.branch, "release-") {
		logrus.Info("Pushing%s %s branch:", dryRunFlag, options.branch)
		if err := repo.PushWithReties(options.branch, 10); err != nil {
			return errors.Wrapf(err, "pushing branch %s", options.branch)
		}

		// Additionally push the parent branch if a branch of branch
		if strings.HasPrefix(options.parentBranch, "release-") {
			logrus.Infof("Pushing%s %s branch: ", dryRunFlag, options.parentBranch)
			if err := repo.PushWithReties(options.parentBranch, 10); err != nil {
				return errors.Wrapf(err, "pushing parent branch %s", options.parentBranch)
			}
		}
	}
	/*
	  # For files created on master with new branches and
	  # for $CHANGELOG_FILEPATH, update the master
	  gitlib::push_master
	*/
	logrus.Info("git objects push complete")
	return nil
}
