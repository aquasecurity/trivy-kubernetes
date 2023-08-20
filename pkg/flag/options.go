package flag

import (
	"fmt"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/spf13/cobra"
)

type Flags struct {
	flag.Flags

	GlobalFlagGroup *flag.GlobalFlagGroup
	K8sFlagGroup    *K8sFlagGroup
}

type Options struct {
	flag.Options

	K8sOptions
}

func (f *Flags) Groups() flag.FlagGroups {
	return append(f.Flags.Groups(), f.K8sFlagGroup, f.GlobalFlagGroup)
}

func (f *Flags) AddFlags(cmd *cobra.Command) {
	f.Groups().Add(cmd)
}

func (f *Flags) ToOptions(args []string) (Options, error) {
	var opts Options
	var err error

	opts.Options, err = f.Flags.ToOptions(args, f.GlobalFlagGroup)
	if err != nil {
		return Options{}, err
	}

	opts.K8sOptions, err = f.K8sFlagGroup.ToOptions()
	if err != nil {
		return Options{}, err
	}
	return opts, nil
}

func (f *Flags) Usages(cmd *cobra.Command) string {
	return fmt.Sprintf(flag.UsageTemplate, f.Groups().Usages(cmd))
}

func (f *Flags) Bind(cmd *cobra.Command) error {
	return f.Groups().Bind(cmd)
}
