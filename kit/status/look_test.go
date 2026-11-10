package status_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/status"
)

const logo = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 32 32">` +
	`<defs><linearGradient id="g"><stop offset="0" stop-color="#2e7d32"/></linearGradient></defs>` +
	`<style>circle{opacity:.9}</style>` +
	`<circle cx="16" cy="16" r="14" fill="url(#g)"/><use xlink:href="#g"/></svg>`

func TestIconFromSVG_WritesADataURIThatCheckIconAccepts(t *testing.T) {
	icon, err := status.IconFromSVG([]byte(logo))
	if err != nil {
		t.Fatal(err)
	}
	b64, ok := strings.CutPrefix(icon, "data:image/svg+xml;base64,")
	if !ok {
		t.Fatalf("icon = %.40q…, want an SVG data URI", icon)
	}
	if svg, _ := base64.StdEncoding.DecodeString(b64); string(svg) != logo {
		t.Errorf("icon carries %q, want the SVG unchanged", svg)
	}
	if err := status.CheckIcon(icon); err != nil {
		t.Errorf("CheckIcon refuses what IconFromSVG wrote: %v", err)
	}
}

func TestIconFromSVG_TakesTheLargestIconAllowed(t *testing.T) {
	svg := padded(status.MaxIconSize)
	icon, err := status.IconFromSVG(svg)
	if err != nil {
		t.Fatalf("an SVG of exactly %d bytes is refused: %v", len(svg), err)
	}
	if err := status.CheckIcon(icon); err != nil {
		t.Errorf("CheckIcon refuses the largest icon: %v", err)
	}
}

// padded returns a valid SVG of exactly n bytes.
func padded(n int) []byte {
	head, tail := `<svg xmlns="http://www.w3.org/2000/svg"><!--`, `--></svg>`
	return []byte(head + strings.Repeat("x", n-len(head)-len(tail)) + tail)
}

func TestIconFromSVG_RefusesWhatCouldRunOrLoadSomething(t *testing.T) {
	const ns = `xmlns="http://www.w3.org/2000/svg"`
	for name, svg := range map[string]string{
		"empty":                  ``,
		"not XML":                `<svg ` + ns + `><circle></svg>`,
		"HTML":                   `<html><body>hi</body></html>`,
		"svg without namespace":  `<svg><circle r="1"/></svg>`,
		"two roots":              `<svg ` + ns + `/><svg ` + ns + `/>`,
		"script":                 `<svg ` + ns + `><script>alert(1)</script></svg>`,
		"script in upper case":   `<svg ` + ns + `><SCRIPT>alert(1)</SCRIPT></svg>`,
		"foreign object":         `<svg ` + ns + `><foreignObject><div xmlns="http://www.w3.org/1999/xhtml">x</div></foreignObject></svg>`,
		"element of another ns":  `<svg ` + ns + `><h:img xmlns:h="http://www.w3.org/1999/xhtml" src="x"/></svg>`,
		"event handler":          `<svg ` + ns + ` onload="alert(1)"/>`,
		"event handler in caps":  `<svg ` + ns + `><circle ONCLICK="alert(1)"/></svg>`,
		"external href":          `<svg ` + ns + `><image href="https://example.org/x.png"/></svg>`,
		"external xlink:href":    `<svg ` + ns + ` xmlns:xlink="http://www.w3.org/1999/xlink"><use xlink:href="other.svg#a"/></svg>`,
		"javascript in a value":  `<svg ` + ns + `><a><set attributeName="href" to="JavaScript:alert(1)"/></a></svg>`,
		"doctype with an entity": `<!DOCTYPE svg [<!ENTITY a "aaaa">]><svg ` + ns + `>&a;</svg>`,
		"css import":             `<svg ` + ns + `><style>@import "https://example.org/x.css";</style></svg>`,
		"doctype":                `<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg ` + ns + `/>`,
		"empty foreign object":   `<svg ` + ns + `><foreignObject width="8" height="8"/></svg>`,
		"css url to elsewhere":   `<svg ` + ns + ` style="fill:url(https://example.org/x.svg#a)"/>`,
		"css escape":             `<svg ` + ns + `><style>@\69mport "https://example.org/x.css";</style></svg>`,
		"css escape in a url":    `<svg ` + ns + ` style="fill:u\72l(https://example.org/x.svg#a)"/>`,
		"css image-set":          `<svg ` + ns + ` style="background:image-set('https://example.org/x.png' 1x)"/>`,
		"animated href":          `<svg ` + ns + `><a><animate attributeName="href" values="https://example.org/"/></a></svg>`,
		"set xlink:href":         `<svg ` + ns + `><a><set attributeName="xlink:href" to="data:text/html,x"/></a></svg>`,
		"stylesheet instruction": `<?xml-stylesheet href="https://example.org/x.css"?><svg ` + ns + `/>`,
	} {
		t.Run(name, func(t *testing.T) {
			if icon, err := status.IconFromSVG([]byte(svg)); err == nil {
				t.Errorf("IconFromSVG accepts it: %.60q…", icon)
			}
			icon := "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svg))
			if status.CheckIcon(icon) == nil {
				t.Errorf("CheckIcon accepts it")
			}
		})
	}
}

func TestIconFromSVG_RefusesAnSVGPastTheLimit(t *testing.T) {
	if _, err := status.IconFromSVG(padded(status.MaxIconSize + 1)); err == nil {
		t.Errorf("an SVG of %d bytes is accepted", status.MaxIconSize+1)
	}
}

func TestCheckIcon_RefusesAnythingButAnSVGDataURI(t *testing.T) {
	good, err := status.IconFromSVG([]byte(logo))
	if err != nil {
		t.Fatal(err)
	}
	b64 := strings.TrimPrefix(good, "data:image/svg+xml;base64,")
	for name, icon := range map[string]string{
		"empty":             "",
		"a web address":     "https://tower.lan/icon.svg",
		"a path":            "/icon.svg",
		"html":              "data:text/html;base64," + b64,
		"png":               "data:image/png;base64," + b64,
		"not base64":        "data:image/svg+xml;base64,<svg>",
		"percent-encoded":   "data:image/svg+xml,%3Csvg%3E",
		"url-safe base64":   "data:image/svg+xml;base64," + strings.NewReplacer("+", "-", "/", "_").Replace(b64) + "-_",
		"upper-case prefix": "DATA:image/svg+xml;base64," + b64,
		"line break":        "data:image/svg+xml;base64," + b64[:8] + "\n" + b64[8:],
		"too large":         "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(padded(status.MaxIconSize+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if status.CheckIcon(icon) == nil {
				t.Errorf("CheckIcon accepts %.60q…", icon)
			}
		})
	}
}

func TestCheckColor(t *testing.T) {
	for _, c := range []string{"#2e7d32", "#2E7D32", "#000000"} {
		if err := status.CheckColor(c); err != nil {
			t.Errorf("CheckColor(%q) = %v, want nil", c, err)
		}
	}
	for _, c := range []string{"", "red", "#fff", "2e7d32", "#2e7d32ff", "#2e7d3g", "#2e7d32;background:url(x)", "rgb(1,2,3)"} {
		if status.CheckColor(c) == nil {
			t.Errorf("CheckColor(%q) = nil, want an error", c)
		}
	}
}
