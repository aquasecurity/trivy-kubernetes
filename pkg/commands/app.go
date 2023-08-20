package commands

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-kubernetes/pkg/compliance"
	k8sflag "github.com/aquasecurity/trivy-kubernetes/pkg/flag"
	"github.com/aquasecurity/trivy-kubernetes/pkg/version"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	xstrings "github.com/aquasecurity/trivy/pkg/x/strings"
)

func NewCmd() *cobra.Command {
	scanFlags := flag.NewScanFlagGroup()
	scanners := flag.ScannersFlag
	scanners.Default = fmt.Sprintf( // overwrite the default value
		"%s,%s,%s,%s",
		types.VulnerabilityScanner,
		types.MisconfigScanner,
		types.SecretScanner,
		types.RBACScanner,
	)
	scanFlags.Scanners = &scanners
	scanFlags.IncludeDevDeps = nil // disable '--include-dev-deps'

	// required only SourceFlag
	imageFlags := &flag.ImageFlagGroup{ImageSources: &flag.SourceFlag}

	reportFlagGroup := flag.NewReportFlagGroup()
	complianceFlag := flag.ComplianceFlag
	complianceFlag.Values = []string{
		compliance.NSA,
		compliance.CIS,
		compliance.PSSBaseline,
		compliance.PSSRestricted,
	}
	reportFlagGroup.Compliance = &complianceFlag // override usage as the accepted values differ for each subcommand.
	reportFlagGroup.ExitOnEOL = nil              // disable '--exit-on-eol'

	formatFlag := flag.FormatFlag
	formatFlag.Values = xstrings.ToStringSlice([]types.Format{
		types.FormatTable,
		types.FormatJSON,
		types.FormatCycloneDX,
	})
	reportFlagGroup.Format = &formatFlag

	k8sFlags := &k8sflag.Flags{
		GlobalFlagGroup: flag.NewGlobalFlagGroup(),
		K8sFlagGroup:    k8sflag.NewK8sFlagGroup(), // kubernetes-specific flags
		Flags: flag.Flags{
			CacheFlagGroup:         flag.NewCacheFlagGroup(),
			DBFlagGroup:            flag.NewDBFlagGroup(),
			ImageFlagGroup:         imageFlags,
			MisconfFlagGroup:       flag.NewMisconfFlagGroup(),
			RegoFlagGroup:          flag.NewRegoFlagGroup(),
			ReportFlagGroup:        reportFlagGroup,
			ScanFlagGroup:          scanFlags,
			SecretFlagGroup:        flag.NewSecretFlagGroup(),
			RegistryFlagGroup:      flag.NewRegistryFlagGroup(),
			VulnerabilityFlagGroup: flag.NewVulnerabilityFlagGroup(),
		},
	}
	cmd := &cobra.Command{
		Version: version.Version(),
		Use:     "trivy-k8s [flags] { cluster | all | specific resources like kubectl. eg: pods, pod/NAME }",
		Short:   "[EXPERIMENTAL] Scan kubernetes cluster",
		Example: `  # cluster scanning
  $ trivy k8s --report summary cluster

  # namespace scanning:
  $ trivy k8s -n kube-system --report summary all

  # resources scanning:
  $ trivy k8s --report=summary deploy
  $ trivy k8s --namespace=kube-system --report=summary deploy,configmaps

  # resource scanning:
  $ trivy k8s deployment/orion
`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// viper.BindPFlag cannot be called in init().
			// cf. https://github.com/spf13/cobra/issues/875
			//     https://github.com/spf13/viper/issues/233
			if err := k8sFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}

			// The config path is needed for config initialization.
			// It needs to be obtained before ToOptions().
			configPath := viper.GetString(flag.ConfigFileFlag.ConfigName)

			// Configure environment variables and config file
			// It cannot be called in init() because it must be called after viper.BindPFlags.
			if err := initConfig(configPath); err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			opts, err := k8sFlags.ToOptions(args)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}

			// Initialize logger
			if err = log.InitLogger(opts.Debug, opts.Quiet); err != nil {
				return err
			}

			return Run(cmd.Context(), args, opts)
		},
		Args:          cobra.MinimumNArgs(1),
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	k8sFlags.AddFlags(cmd)
	cmd.SetUsageTemplate(k8sFlags.Usages(cmd))

	return cmd

}

func initConfig(configFile string) error {
	// Read from config
	viper.SetConfigFile(configFile)
	viper.SetConfigType("yaml")
	if err := viper.ReadInConfig(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Logger.Debugf("config file %q not found", configFile)
			return nil
		}
		return xerrors.Errorf("config file %q loading error: %s", configFile, err)
	}
	log.Logger.Infof("Loaded %s", configFile)
	return nil
}
