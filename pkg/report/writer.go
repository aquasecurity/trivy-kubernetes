package report

import (
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/aquasecurity/trivy/pkg/report/table"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Writer interface {
	Write(Report) error
}

// Write writes the results in the give format
func Write(report Report, option Option) error {
	report.PrintErrors()

	switch option.Format {
	case types.FormatJSON:
		jwriter := JSONWriter{
			Output: option.Output,
			Report: option.Report,
		}
		return jwriter.Write(report)
	case types.FormatTable:
		separatedReports := SeparateMisconfigReports(report, option.Scanners, option.Components)

		if option.Report == SummaryReport {
			target := fmt.Sprintf("Summary Report for %s", report.ClusterName)
			table.RenderTarget(option.Output, target, table.IsOutputToTerminal(option.Output))
		}

		for _, r := range separatedReports {
			writer := &TableWriter{
				Output:        option.Output,
				Report:        option.Report,
				Severities:    option.Severities,
				ColumnHeading: ColumnHeading(option.Scanners, option.Components, r.Columns),
			}

			if err := writer.Write(r.Report); err != nil {
				return err
			}
		}

		return nil
	case types.FormatCycloneDX:
		w := NewCycloneDXWriter(option.Output, cdx.BOMFileFormatJSON, option.APIVersion)
		return w.Write(report.RootComponent)
	}
	return nil
}
