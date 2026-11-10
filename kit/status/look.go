package status

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// MaxIconSize is the most bytes the SVG behind App.Icon may have, which keeps
// a report with an icon well inside the 64 KiB a report may take.
const MaxIconSize = 16 << 10

const (
	iconPrefix = "data:image/svg+xml;base64,"
	svgSpace   = "http://www.w3.org/2000/svg"
)

var hexColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// CheckColor reports whether c is a colour of the form #rrggbb, the only form
// App.Color takes, so a reader can put it into CSS as it is.
func CheckColor(c string) error {
	if !hexColor.MatchString(c) {
		return fmt.Errorf("status: color %.40q is not of the form #rrggbb", c)
	}
	return nil
}

// IconFromSVG checks svg as CheckIcon does and returns it as the data URI that
// App.Icon carries.
func IconFromSVG(svg []byte) (string, error) {
	if err := checkSVG(svg); err != nil {
		return "", err
	}
	return iconPrefix + base64.StdEncoding.EncodeToString(svg), nil
}

// CheckIcon reports whether icon is an SVG data URI in standard base64 whose
// SVG has at most MaxIconSize bytes and draws a plain picture: no script, no
// event handler, no element outside the SVG namespace, no DOCTYPE and no
// reference to anything outside itself.
//
// Readers show an icon only through an img element, where browsers neither run
// script nor load anything else; the check covers a reader that slips.
func CheckIcon(icon string) error {
	b64, ok := strings.CutPrefix(icon, iconPrefix)
	if !ok {
		return errors.New("status: icon is not a data:image/svg+xml;base64 URI")
	}
	svg, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil || base64.StdEncoding.EncodeToString(svg) != b64 {
		return errors.New("status: icon is not in standard base64")
	}
	return checkSVG(svg)
}

func checkSVG(svg []byte) error {
	if len(svg) > MaxIconSize {
		return fmt.Errorf("status: icon has %d bytes, more than %d", len(svg), MaxIconSize)
	}
	d := xml.NewDecoder(bytes.NewReader(svg))
	depth, roots := 0, 0
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("status: icon is not well-formed XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if depth == 0 {
				roots++
				if roots > 1 || t.Name.Local != "svg" {
					return errors.New("status: icon is not a single svg element")
				}
			}
			if err := checkElement(t); err != nil {
				return err
			}
			depth++
		case xml.EndElement:
			depth--
		case xml.CharData:
			if err := checkText(string(t)); err != nil {
				return err
			}
		case xml.Directive:
			return errors.New("status: icon has a DOCTYPE or another directive")
		case xml.ProcInst:
			if t.Target != "xml" {
				return fmt.Errorf("status: icon has the processing instruction %q", t.Target)
			}
		}
	}
	if roots == 0 {
		return errors.New("status: icon is empty")
	}
	return nil
}

func checkElement(e xml.StartElement) error {
	if e.Name.Space != svgSpace {
		return fmt.Errorf("status: icon has the element %q outside the SVG namespace", e.Name.Local)
	}
	switch strings.ToLower(e.Name.Local) {
	case "script", "foreignobject":
		return fmt.Errorf("status: icon has a %s element", e.Name.Local)
	}
	for _, a := range e.Attr {
		name := strings.ToLower(a.Name.Local)
		if strings.HasPrefix(name, "on") {
			return fmt.Errorf("status: icon has the event handler %s", a.Name.Local)
		}
		if name == "href" && !strings.HasPrefix(a.Value, "#") {
			return errors.New("status: icon refers to something outside itself")
		}
		if err := checkText(a.Value); err != nil {
			return err
		}
	}
	return nil
}

// cssURL finds the start of every url() in text, up to its first character.
var cssURL = regexp.MustCompile(`(?i)url\(\s*['"]?\s*(.?)`)

// checkText refuses text and attribute values that name a script URL or make
// CSS load something from elsewhere; url(#id) for gradients and masks stays.
func checkText(s string) error {
	lower := strings.ToLower(s)
	if strings.Contains(strings.Join(strings.Fields(lower), ""), "javascript:") {
		return errors.New("status: icon has a javascript: URL")
	}
	if strings.Contains(lower, "@import") {
		return errors.New("status: icon imports CSS")
	}
	for _, m := range cssURL.FindAllStringSubmatch(s, -1) {
		if m[1] != "#" {
			return errors.New("status: icon refers to something outside itself")
		}
	}
	return nil
}
