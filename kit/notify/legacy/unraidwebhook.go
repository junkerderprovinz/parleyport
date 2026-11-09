package legacy

import "github.com/junkerderprovinz/parleyport/kit/notify"

// FromUnraidWebhook reads {"unraid": bool, "webhook": url}: Unraid's own
// notifications and a webhook that got {"event", "detail", "importance"}
// within ten seconds. Every alert went to both, so each gets On always.
func FromUnraidWebhook(data []byte) ([]notify.Channel, error) {
	var n struct {
		Unraid  bool   `json:"unraid"`
		Webhook string `json:"webhook"`
	}
	if err := decode(data, &n); err != nil {
		return nil, err
	}
	var out []notify.Channel
	if n.Unraid {
		out = append(out, notify.Channel{ID: "unraid", Kind: notify.KindUnraid, Enabled: true, On: notify.OnAlways})
	}
	if filled(n.Webhook) {
		out = append(out, notify.Channel{ID: "webhook", Kind: notify.KindWebhook, Enabled: true, On: notify.OnAlways, TimeoutSeconds: 10,
			Webhook: jsonWebhook(n.Webhook, `{"event":"%%title%%","detail":"%%body%%","importance":"%%importance%%"}`)})
	}
	return settled(out), nil
}
