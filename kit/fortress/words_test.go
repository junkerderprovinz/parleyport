package fortress

import (
	"net/http/httptest"
	"strings"
	"testing"
	"unicode"
)

func TestWordsCoverEveryCodeInEveryLanguage(t *testing.T) {
	codes := []string{"closed", "removed", "unreachable", "permission_off", "no_ui", "too_large", "ui_no_login", "busy", "other"}
	if len(sentences) != 42 {
		t.Errorf("%d languages, want 42", len(sentences))
	}
	for lang, words := range sentences {
		if len(words) != len(codes) {
			t.Errorf("%s has %d sentences, want %d", lang, len(words), len(codes))
		}
		for _, code := range codes {
			s := strings.TrimSpace(words[code])
			if s == "" {
				t.Errorf("%s has no sentence for %s", lang, code)
			}
			if strings.ContainsFunc(s, func(r rune) bool { return unicode.Is(unicode.Pd, r) && r != '-' }) {
				t.Errorf("%s %s has a dash: %q", lang, code, s)
			}
		}
	}
}

func TestWordsSpeakTheLanguageTheBrowserAsksFor(t *testing.T) {
	for _, tc := range []struct{ header, want string }{
		{"de-AT,de;q=0.9,en;q=0.8", "de"},
		{"fr;q=0.2, xx", "fr"},
		{"", "en"},
		{"pt-BR", "pt"},
		{"zh-CN,zh;q=0.9", "zh"},
		{"nb-NO", "no"},
		{"xx, de;q=0", "en"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		if tc.header != "" {
			r.Header.Set("Accept-Language", tc.header)
		}
		if got, want := Words(r, "closed"), sentences[tc.want]["closed"]; got != want {
			t.Errorf("Accept-Language %q: %q, want %q", tc.header, got, want)
		}
	}
}

func TestWordsSayTheAppSentSomethingForAnUnknownCode(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if got := Words(r, "bad_answer"); got != "The app sent something that can't be shown here." {
		t.Errorf("bad_answer: %q", got)
	}
}
