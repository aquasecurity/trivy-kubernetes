package report

import (
	"bytes"
	"github.com/stretchr/testify/require"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestReportWrite_Summary(t *testing.T) {
	allSeverities := []dbTypes.Severity{
		dbTypes.SeverityUnknown,
		dbTypes.SeverityLow,
		dbTypes.SeverityMedium,
		dbTypes.SeverityHigh,
		dbTypes.SeverityCritical,
	}

	tests := []struct {
		name           string
		report         Report
		opt            Option
		scanners       types.Scanners
		components     []string
		severities     []dbTypes.Severity
		expectedOutput string
	}{
		{
			name: "Only config, all serverities",
			report: Report{
				ClusterName: "test",
				Resources:   []Resource{deployOrionWithMisconfigs},
			},
			scanners:   types.Scanners{types.MisconfigScanner},
			components: []string{workloadComponent},
			severities: allSeverities,
			expectedOutput: `Summary Report for test
=======================

Workload Assessment
┌───────────┬──────────────┬───────────────────┐
│ Namespace │   Resource   │ Misconfigurations │
│           │              ├───┬───┬───┬───┬───┤
│           │              │ C │ H │ M │ L │ U │
├───────────┼──────────────┼───┼───┼───┼───┼───┤
│ default   │ Deploy/orion │ 1 │ 2 │ 1 │ 2 │ 1 │
└───────────┴──────────────┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN`,
		},
		{
			name: "Only vuln, all serverities",
			report: Report{
				ClusterName: "test",
				Resources:   []Resource{deployOrionWithVulns},
			},
			scanners:   types.Scanners{types.VulnerabilityScanner},
			severities: allSeverities,
			expectedOutput: `Summary Report for test
=======================

Workload Assessment
┌───────────┬──────────────┬───────────────────┐
│ Namespace │   Resource   │  Vulnerabilities  │
│           │              ├───┬───┬───┬───┬───┤
│           │              │ C │ H │ M │ L │ U │
├───────────┼──────────────┼───┼───┼───┼───┼───┤
│ default   │ Deploy/orion │ 2 │ 1 │ 2 │ 1 │ 1 │
└───────────┴──────────────┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN`,
		},
		{
			name: "Only rbac, all serverities",
			report: Report{
				ClusterName: "test",
				Resources:   []Resource{roleWithMisconfig},
			},
			scanners:   types.Scanners{types.RBACScanner},
			severities: allSeverities,
			expectedOutput: `Summary Report for test
=======================

RBAC Assessment
┌───────────┬─────────────────────────────────────────────────────┬───────────────────┐
│ Namespace │                      Resource                       │  RBAC Assessment  │
│           │                                                     ├───┬───┬───┬───┬───┤
│           │                                                     │ C │ H │ M │ L │ U │
├───────────┼─────────────────────────────────────────────────────┼───┼───┼───┼───┼───┤
│ default   │ Role/system::leader-locking-kube-controller-manager │   │   │ 1 │   │   │
└───────────┴─────────────────────────────────────────────────────┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN`,
		},
		{
			name: "Only secret, all serverities",
			report: Report{
				ClusterName: "test",
				Resources:   []Resource{deployLuaWithSecrets},
			},
			scanners:   types.Scanners{types.SecretScanner},
			severities: allSeverities,
			expectedOutput: `Summary Report for test
=======================

Workload Assessment
┌───────────┬────────────┬───────────────────┐
│ Namespace │  Resource  │      Secrets      │
│           │            ├───┬───┬───┬───┬───┤
│           │            │ C │ H │ M │ L │ U │
├───────────┼────────────┼───┼───┼───┼───┼───┤
│ default   │ Deploy/lua │ 1 │   │ 1 │   │   │
└───────────┴────────────┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN`,
		},
		{
			name: "apiserver, only infra and serverities",
			report: Report{
				ClusterName: "test",
				Resources:   []Resource{apiseverPodWithMisconfigAndInfra},
			},
			scanners:   types.Scanners{types.MisconfigScanner},
			components: []string{infraComponent},
			severities: allSeverities,
			expectedOutput: `Summary Report for test
=======================

Infra Assessment
┌─────────────┬────────────────────┬─────────────────────────────┐
│  Namespace  │      Resource      │ Kubernetes Infra Assessment │
│             │                    ├─────┬─────┬─────┬─────┬─────┤
│             │                    │  C  │  H  │  M  │  L  │  U  │
├─────────────┼────────────────────┼─────┼─────┼─────┼─────┼─────┤
│ kube-system │ Pod/kube-apiserver │     │     │ 1   │ 1   │     │
└─────────────┴────────────────────┴─────┴─────┴─────┴─────┴─────┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN`,
		},
		{
			name: "apiserver, vuln,config,secret and serverities",
			report: Report{
				ClusterName: "test",
				Resources:   []Resource{apiseverPodWithMisconfigAndInfra},
			},
			scanners: types.Scanners{
				types.VulnerabilityScanner,
				types.MisconfigScanner,
				types.SecretScanner,
			},
			components: []string{workloadComponent},
			severities: allSeverities,
			expectedOutput: `Summary Report for test
=======================

Workload Assessment
┌─────────────┬────────────────────┬───────────────────┬───────────────────┬───────────────────┐
│  Namespace  │      Resource      │  Vulnerabilities  │ Misconfigurations │      Secrets      │
│             │                    ├───┬───┬───┬───┬───┼───┬───┬───┬───┬───┼───┬───┬───┬───┬───┤
│             │                    │ C │ H │ M │ L │ U │ C │ H │ M │ L │ U │ C │ H │ M │ L │ U │
├─────────────┼────────────────────┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┤
│ kube-system │ Pod/kube-apiserver │   │   │   │   │   │   │ 1 │ 1 │ 1 │   │   │   │   │   │   │
└─────────────┴────────────────────┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN`,
		},
		{
			name: "apiserver, all scanners and serverities",
			report: Report{
				ClusterName: "test",
				Resources:   []Resource{apiseverPodWithMisconfigAndInfra},
			},
			scanners: types.Scanners{
				types.MisconfigScanner,
				types.VulnerabilityScanner,
				types.RBACScanner,
				types.SecretScanner,
			},
			components: []string{
				workloadComponent,
				infraComponent,
			},
			severities: allSeverities,
			expectedOutput: `Summary Report for test
=======================

Workload Assessment
┌─────────────┬────────────────────┬───────────────────┬───────────────────┬───────────────────┐
│  Namespace  │      Resource      │  Vulnerabilities  │ Misconfigurations │      Secrets      │
│             │                    ├───┬───┬───┬───┬───┼───┬───┬───┬───┬───┼───┬───┬───┬───┬───┤
│             │                    │ C │ H │ M │ L │ U │ C │ H │ M │ L │ U │ C │ H │ M │ L │ U │
├─────────────┼────────────────────┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┤
│ kube-system │ Pod/kube-apiserver │   │   │   │   │   │   │ 1 │ 1 │ 1 │   │   │   │   │   │   │
└─────────────┴────────────────────┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN


Infra Assessment
┌─────────────┬────────────────────┬─────────────────────────────┐
│  Namespace  │      Resource      │ Kubernetes Infra Assessment │
│             │                    ├─────┬─────┬─────┬─────┬─────┤
│             │                    │  C  │  H  │  M  │  L  │  U  │
├─────────────┼────────────────────┼─────┼─────┼─────┼─────┼─────┤
│ kube-system │ Pod/kube-apiserver │     │     │ 1   │ 1   │     │
└─────────────┴────────────────────┴─────┴─────┴─────┴─────┴─────┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output := bytes.Buffer{}

			opt := Option{
				Format:     "table",
				Report:     "summary",
				Output:     &output,
				Scanners:   tc.scanners,
				Severities: tc.severities,
				Components: tc.components,
			}

			err := Write(tc.report, opt)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedOutput, stripAnsi(output.String()), tc.name)
		})
	}
}

const ansi = "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"

var ansiRegexp = regexp.MustCompile(ansi)

func stripAnsi(str string) string {
	return strings.TrimSpace(ansiRegexp.ReplaceAllString(str, ""))
}
