package notes

/*
Copyright 2017 The Kubernetes Authors.

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

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/yaml"
)

// MapProvider interface that obtains release notes maps from a source
type MapProvider interface {
	// GetMaps
	GetMaps() ([]*ReleaseNotesMap, error)
	// Get a ReleaseNotesMap for a specific commit
	GetMap(int) (*ReleaseNotesMap, error)
}

// NewProviderFromInitString creates a new map provider from an initialization string
func NewProviderFromInitString(initString string) (MapProvider, error) {
	// DirectoryProvider
	if initString[0:4] == "dir" {
		parts := strings.Split(initString, ":")
		if len(parts) != 2 {
			return nil, errors.New("map provider initialization string is not well formed")
		}

		return &DirectoryMapProvider{
			Path: parts[1],
		}, nil
	}

	return nil, errors.New("Unkown map provider in init string")
}

// ParseReleaseNotesMap Parses a Release Notes Map
func ParseReleaseNotesMap(mapPath string) (notemap *ReleaseNotesMap, err error) {
	notemap = &ReleaseNotesMap{}
	yamlData, err := ioutil.ReadFile(mapPath)
	if err != nil {
		return notemap, errors.Wrap(err, "reading map yaml")
	}
	if err := yaml.Unmarshal(yamlData, &notemap); err != nil {
		return notemap, errors.Wrap(err, "while unmarshaling map yaml")
	}

	// PR number is always required
	if notemap.PR == 0 {
		return nil, errors.New(fmt.Sprintf("Note map at %s does not have a PR number", mapPath))
	}
	// logrus.Infof("Note Value:\n%+v", notemap)
	return notemap, nil
}

// ReleaseNotesMap Represents
type ReleaseNotesMap struct {
	// Pull request where the note was published
	PR int `json:"pr"`
	// SHA of the notes commit
	Commit      string `json:"commit"`
	ReleaseNote struct {
		// Text is the actual content of the release note
		Text string `json:"text"`

		// Docs is additional documentation for the release note
		Documentation []*Documentation `json:"documentation,omitempty"`

		// Author is the GitHub username of the commit author
		Author string `json:"author"`

		// Areas is a list of the labels beginning with area/
		Areas []string `json:"areas,omitempty"`

		// Kinds is a list of the labels beginning with kind/
		Kinds []string `json:"kinds,omitempty"`

		// SIGs is a list of the labels beginning with sig/
		SIGs []string `json:"sigs,omitempty"`

		// Indicates whether or not a note will appear as a new feature
		Feature *bool `json:"feature,omitempty"`

		// ActionRequired indicates whether or not the release-note-action-required
		// label was set on the PR
		ActionRequired *bool `json:"action_required,omitempty"`

		// Tags each note with a release version if specified
		// If not specified, omitted
		ReleaseVersion string `json:"release_version,omitempty"`
	} `json:"release-note"`

	DataFields map[string]ReleaseNotesDataField `json:"datafields"`
}

// ReleaseNotesDataField extra data added to a release note
type ReleaseNotesDataField interface{}

// DirectoryMapProvider is a provider that gets maps from a directory
type DirectoryMapProvider struct {
	Path string
	Maps map[int]*ReleaseNotesMap
}

// readMaps Open the dir and read dir notes
func (mp *DirectoryMapProvider) readMaps() error {

	var fileList []string
	mp.Maps = map[int]*ReleaseNotesMap{}

	err := filepath.Walk(mp.Path, func(path string, info os.FileInfo, err error) error {
		if filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml" {
			fileList = append(fileList, path)
		}
		return nil
	})

	for _, fileName := range fileList {
		notemap, err := ParseReleaseNotesMap(fileName)
		if err != nil {
			logrus.Warnf("while reading parsing note at %s", fileName)
			continue
		}
		mp.Maps[notemap.PR] = notemap

		fmt.Printf("%+v", mp)
	}
	logrus.Infof("Succesfully parsed %d release notes maps from %s", len(mp.Maps), mp.Path)
	return err
}

// GetMap get a map by PR number
func (mp *DirectoryMapProvider) GetMap(pr int) (notesMap *ReleaseNotesMap, err error) {
	if mp.Maps == nil {
		err := mp.readMaps()
		if err != nil {
			return nil, errors.Wrap(err, "while reading release notes maps")
		}
	}
	if notesMap, ok := mp.Maps[pr]; ok {
		return notesMap, nil
	}
	return nil, nil
}

// GetMaps return all release notes map found by the provider
func (mp *DirectoryMapProvider) GetMaps() ([]*ReleaseNotesMap, error) {
	return nil, nil
}
