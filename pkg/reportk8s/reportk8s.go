package reportk8s

import (
	"fmt"
	"os"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/olekukonko/tablewriter"
)

type KubernetesReport struct {
	Namespace string
	Name      string
	Kind      string
	Image     string
	Results   types.Results
}

func PrintImagesReport(reports []KubernetesReport) {
	var isMisconfig bool

	var data [][]string
	for _, r := range reports {
		d := make([]string, 4)
		d[0] = r.Namespace

		if len(r.Image) == 0 {
			d[1] = r.Kind
			d[2] = r.Name
		} else {
			d[1] = fmt.Sprintf("%s/%s", r.Kind, r.Name)
			d[2] = r.Image
		}

		for _, rr := range r.Results {
			var critical, high, medium, low, unknown int
			for _, vuln := range rr.Vulnerabilities {
				switch vuln.Severity {
				case "CRITICAL":
					critical++
				case "HIGH":
					high++
				case "MEDIUM":
					medium++
				case "LOW":
					low++
				case "UNKNOWN":
					unknown++
				}

				d[3] = fmt.Sprintf(
					"CRITICAL: %d, HIGH: %d, MEDIUM: %d, LOW: %d, UNKNOWN: %d",
					critical,
					high,
					medium,
					low,
					unknown,
				)
			}

			for _, mis := range rr.Misconfigurations {
				isMisconfig = true
				switch mis.Severity {
				case "CRITICAL":
					critical++
				case "HIGH":
					high++
				case "MEDIUM":
					medium++
				case "LOW":
					low++
				case "UNKNOWN":
					unknown++
				}

				d[3] = fmt.Sprintf(
					"CRITICAL: %d, HIGH: %d, MEDIUM: %d, LOW: %d, UNKNOWN: %d",
					critical,
					high,
					medium,
					low,
					unknown,
				)
			}

		}
		data = append(data, d)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.AppendBulk(data)

	if isMisconfig {
		table.SetHeader([]string{
			"Namespace",
			"Kind",
			"Name",
			"Vunerabilities",
		})
	} else {
		table.SetHeader([]string{
			"Namespace",
			"Resource",
			"Image",
			"Vunerabilities",
		})

	}

	table.SetRowLine(true)
	table.Render() // Send output
}
