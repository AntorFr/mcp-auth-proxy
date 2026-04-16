package repository

import (
	"context"
	"encoding/json"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/pkce"
)

type Repository interface {
	fosite.Storage
	oauth2.CoreStorage
	oauth2.TokenRevocationStorage
	pkce.PKCERequestStorage
	DynamicClientStorage
	AuthorizeRequestStorage
	Close() error
}

type DynamicClientStorage interface {
	RegisterClient(ctx context.Context, client fosite.Client) error
}

type AuthorizeRequestStorage interface {
	CreateAuthorizeRequest(ctx context.Context, request fosite.AuthorizeRequester) error
	GetAuthorizeRequest(ctx context.Context, requestID string) (fosite.AuthorizeRequester, error)
	DeleteAuthorizeRequest(ctx context.Context, requestID string) error
}

func restoreSession(req *fosite.Request, sessionData json.RawMessage, sess fosite.Session) {
	if len(sessionData) > 0 && sess != nil {
		if json.Unmarshal(sessionData, sess) == nil {
			req.SetSession(sess)
		}
	}
}
