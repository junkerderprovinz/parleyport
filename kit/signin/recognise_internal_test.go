package signin

import "testing"

func TestADiscoveryThatFitsTwoPresetsIsCustom(t *testing.T) {
	if got := recognise("https://id.example/oauth/v2/authorize", "https://id.example/api/oidc/token"); got != "custom" {
		t.Fatalf("an endpoint pair of two presets is %s", got)
	}
	if got := recognise("https://id.example/oauth/v2/authorize", "https://id.example/oauth/v2/token"); got != "zitadel" {
		t.Fatalf("zitadel's endpoints are %s", got)
	}
}
