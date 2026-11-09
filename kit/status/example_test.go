package status_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/junkerderprovinz/parleyport/kit/status"
)

// exampleApp reports one stale copy and keeps no log yet.
type exampleApp struct{}

func (exampleApp) Report(_ context.Context, lang string) (status.Report, error) {
	text := "The off-site copy is 9 days old."
	if lang == "de" {
		text = "Die Off-site-Kopie ist 9 Tage alt."
	}
	return status.Report{
		App:      status.App{ID: "example-app", Name: "Example", Version: "1.0.0"},
		Instance: status.Instance{ID: "a1", Name: "Tower"},
		State:    status.StateOK,
		NeedsYou: []status.Need{{ID: "offsite-stale", Severity: status.SeverityWarn, Code: "offsite.stale", Text: text}},
	}, nil
}

func (exampleApp) Log(_ context.Context, q status.LogQuery) (status.LogPage, error) {
	return status.LogPage{Next: q.After}, nil
}

func ExampleHandler() {
	h := status.Handler(exampleApp{}, func(r *http.Request) error {
		if r.Header.Get("Authorization") != "Bearer example-token" {
			return status.ErrUnauthenticated
		}
		return nil
	})
	mux := http.NewServeMux()
	mux.Handle(status.StatusPath, h)
	mux.Handle(status.LogPath, h)

	r := httptest.NewRequest(http.MethodGet, status.StatusPath+"?lang=de", nil)
	r.Header.Set("Authorization", "Bearer example-token")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	var rep status.Report
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		panic(err)
	}
	fmt.Println(w.Code, rep.State, rep.Counts.NeedsYou, rep.NeedsYou[0].Text)
	// Output: 200 warning 1 Die Off-site-Kopie ist 9 Tage alt.
}
