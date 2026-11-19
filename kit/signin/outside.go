package signin

import "context"

func (a *Auth) proxyLogout(context.Context) string { return "" }

func (a *Auth) pauseOutside(context.Context) ([]Doc, error) { return nil, nil }
