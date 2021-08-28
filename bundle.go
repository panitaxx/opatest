package opatest

import (
	"fmt"
	"io"
	"time"

	"github.com/open-policy-agent/opa/bundle"
)

func PublishBundleRSA(key string, wr io.Writer) error {

	manifest := bundle.Manifest{
		Revision: fmt.Sprint(time.Now().Unix()),
	}
	manifest.Init()

	modules := []bundle.ModuleFile{
		{
			URL:  "test",
			Path: "",
			Raw: []byte(`package example.rules

			 any_public_networks {
					 net := input.networks[_]
					 net.public
			 }`),
		},
	}

	var bun bundle.Bundle = bundle.Bundle{
		Modules:  modules,
		Manifest: manifest,
		Data:     map[string]interface{}{},
	}

	if err := bun.FormatModules(false); err != nil {
		return err
	}

	signingConfig := bundle.NewSigningConfig(key, "RS256", "")

	if err := bun.GenerateSignature(signingConfig, "mykey", false); err != nil {
		return err
	}

	bWriter := bundle.NewWriter(wr)

	if err := bWriter.Write(bun); err != nil {
		return err
	}

	return nil
}
