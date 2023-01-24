package jobs

import (
	"embed"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

const jobFSFolder = "template"

var (
	//go:embed template
	jobFS embed.FS
)

var jobTemplateMap map[string]string

// Load job templates
func init() {
	dir, _ := jobFS.ReadDir(jobFSFolder)
	jobTemplateMap = make(map[string]string, 0)
	for _, r := range dir {
		if !strings.Contains(r.Name(), ".yaml") {
			continue
		}
		file, err := jobFS.Open(fmt.Sprintf("%s/%s", jobFSFolder, r.Name()))
		if err != nil {
			panic(err)
		}
		templateContent, err := io.ReadAll(file)
		if err != nil {
			panic(err)
		}
		var fileTemp map[string]interface{}
		err = yaml.Unmarshal(templateContent, &fileTemp)
		if err != nil {
			panic(err)
		}
		if specVal, ok := fileTemp["metadata"].(map[string]interface{}); ok {
			if nameVal, ok := specVal["name"].(string); ok {
				jobTemplateMap[nameVal] = string(templateContent)
			}
		}
	}
}

// GetTemplate returns the spec content
func getTemplate(name string) string {
	if template, ok := jobTemplateMap[name]; ok { // use embedded spec
		return template
	}
	return ""
}
