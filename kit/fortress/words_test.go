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

// passwordWords are each language's word for a password, as the sentences
// write it.
var passwordWords = map[string]string{
	"ar": "كلمة مرور", "bg": "парола", "ca": "contrasenya", "cs": "heslo", "da": "adgangskode",
	"de": "Passwort", "el": "κωδικό", "en": "password", "es": "contraseña", "et": "parool",
	"eu": "pasahitz", "fa": "رمز", "fi": "salasana", "fr": "mot de passe", "gl": "contrasinal",
	"he": "סיסמה", "hi": "पासवर्ड", "hr": "lozink", "hu": "jelsz", "id": "kata sandi",
	"is": "lykilorð", "it": "password", "ja": "パスワード", "ko": "비밀번호", "lt": "slaptažod",
	"lv": "parol", "ms": "kata laluan", "nl": "wachtwoord", "no": "passord", "pl": "hasł",
	"pt": "palavra-passe", "ro": "parol", "ru": "парол", "sk": "heslo", "sl": "geslo",
	"sr": "лозинк", "sv": "lösenord", "th": "รหัสผ่าน", "tr": "parola", "uk": "пароль",
	"vi": "mật khẩu", "zh": "密码",
}

// Only a member on an older kit still refuses, where a password would not
// help.
func TestAnOlderMembersRefusalAsksForAnUpdate(t *testing.T) {
	if got := sentences["en"]["ui_no_login"]; got != "This app needs an update before you can open it from here." {
		t.Errorf("en ui_no_login: %q", got)
	}
	if len(passwordWords) != len(sentences) {
		t.Errorf("%d password words for %d languages", len(passwordWords), len(sentences))
	}
	for lang, word := range passwordWords {
		if s := sentences[lang]["ui_no_login"]; strings.Contains(strings.ToLower(s), strings.ToLower(word)) {
			t.Errorf("%s ui_no_login still asks for a password: %q", lang, s)
		}
	}
}
