package signin

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type enum struct {
	Enum       []string `yaml:"enum"`
	Properties struct {
		Error struct {
			Enum []string `yaml:"enum"`
		} `yaml:"error"`
	} `yaml:"properties"`
}

type spec struct {
	Paths      map[string]map[string]any `yaml:"paths"`
	Components struct {
		Schemas map[string]enum `yaml:"schemas"`
	} `yaml:"components"`
}

func readSpec(t *testing.T) spec {
	t.Helper()
	var s spec
	if err := yaml.Unmarshal(OpenAPI, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestTheContractListsEveryRoute(t *testing.T) {
	var inSpec []string
	for path, ops := range readSpec(t).Paths {
		for method := range ops {
			if method != "parameters" {
				inSpec = append(inSpec, strings.ToUpper(method)+" "+strings.TrimPrefix(path, "/"))
			}
		}
	}
	var served []string
	for _, rt := range (&Auth{}).api() {
		served = append(served, rt.pattern)
	}
	same(t, "route", served, inSpec)
}

// Codes reach the client through fail, or through a helper that returns one
// for fail, and on the way back from a sign-in service through back.
var (
	apiCode      = regexp.MustCompile(`fail\(w, http\.Status\w+, "(\w+)"|refuse\(http\.Status\w+, "(\w+)"\)|return "([a-z]+[A-Z]\w*)"`)
	redirectCode = regexp.MustCompile(`back\(w, r, [^,]+, "(\w+)"\)|note\(Entry\{[^}]*\}, "(\w+)"\)|code :?= "(\w+)"`)
)

func codesIn(t *testing.T, re *regexp.Regexp) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			for _, c := range m[1:] {
				if c != "" && !slices.Contains(out, c) {
					out = append(out, c)
				}
			}
		}
	}
	return out
}

func TestTheContractListsEveryErrorCode(t *testing.T) {
	same(t, "error code", codesIn(t, apiCode), readSpec(t).Components.Schemas["Error"].Properties.Error.Enum)
}

func TestTheContractListsEveryRedirectCode(t *testing.T) {
	same(t, "redirect code", codesIn(t, redirectCode), readSpec(t).Components.Schemas["RedirectCode"].Enum)
}

func same(t *testing.T, what string, code, spec []string) {
	t.Helper()
	for _, c := range code {
		if !slices.Contains(spec, c) {
			t.Errorf("%s %s is in the code but not in openapi.yaml", what, c)
		}
	}
	for _, c := range spec {
		if !slices.Contains(code, c) {
			t.Errorf("%s %s is in openapi.yaml but not in the code", what, c)
		}
	}
}
