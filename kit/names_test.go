package kit_test

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// appNames are the SHA-256 of the apps that use the kit, in lower case, so
// that this file does not name them either.
var appNames = map[string]bool{
	"f4ea3d0db6ba6dd6610d7377cfc727f49da8aebbf72b37d2cff8cca913f508c4": true,
	"4262e1304076feffcc61b260fd87fee3d3458085d337fe4af71562a46d68477d": true,
	"286bdbecadc403e9349dae0d08334fce2bd6e95d46856c5c3841405d93fd7d4e": true,
	"60c767ec2d09836aa42367257389106e473863fa943b87fdfa4d73d5d5ac1008": true,
	"bd6d420828b3e32162192314f7d0cb35b4cd56d14b53aeb2cad3f3210ed3af30": true,
	"a11a3aae35ae5fc2345bf9fedaa66a2e9fa6802f97083cd2bac39ab3435e3cec": true,
	"854cb67af0146dcbf88a9946e71be7ec0978b788d71514f30f953e6a9db09319": true,
	"2bcfe5ff13f646fac69d7bea4a7451fdd564a88f318dbed56f78a1410f555845": true,
	"8b10a9e247dc6d0cf5b86e017c083a1676275457c074b9ac3fabe0413eda3314": true,
	"e67603e525b344b9729eaa76f0d300398cf50ca25bbdc73c23f6089251fc68f4": true,
}

// helloLabel matches the one label the relay checks for every app, which
// keeps the spelling it was introduced under.
var helloLabel = regexp.MustCompile(`[A-Za-z0-9]+/relay/member-hello/v3`)

var word = regexp.MustCompile(`[a-z0-9]+`)

// The kit names no app in code, comments, tests or docs. Only testdata holds
// the domains apps derive their keys under today, as data the vectors need.
func TestTheKitNamesNoApp(t *testing.T) {
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for n, line := range strings.Split(string(raw), "\n") {
			line = helloLabel.ReplaceAllString(line, "")
			for _, w := range word.FindAllString(strings.ToLower(line), -1) {
				sum := sha256.Sum256([]byte(w))
				if appNames[hex.EncodeToString(sum[:])] {
					t.Errorf("%s:%d names an app: %s", filepath.ToSlash(path), n+1, strings.TrimSpace(line))
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
