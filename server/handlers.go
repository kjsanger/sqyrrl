/*
 * Copyright (C) 2024. Genome Research Ltd. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License,
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"io/fs"
	"net/http"
	"path"
	"time"

	"github.com/cyverse/go-irodsclient/irods/types"
	"github.com/rs/xid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
)

// HandlerChain is a function that takes an http.Handler and returns a new http.Handler
// wrapping the input handler. Each handler in the chain should process the request in
// some way, and then call the next handler. Ideally, the functionality of each handler
// should be orthogonal to the others.
//
// This is sometimes called "middleware" in Go. I haven't used that term here because it
// already has an established meaning in the context of operating systems and networking.
type HandlerChain func(http.Handler) http.Handler

// HandleHomePage is a handler for the static home page.
func HandleHomePage(logger zerolog.Logger, index *ItemIndex) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Trace().Msg("HomeHandler called")

		requestPath := r.URL.Path
		requestmethod := r.Method

		if requestPath != "/" && requestmethod == "GET" {
			redirect := path.Join(EndPointIRODS, requestPath)
			logger.Trace().
				Str("from", requestPath).
				Str("to", redirect).
				Str("method", requestmethod).
				Msg("Redirecting to API")
			http.Redirect(w, r, redirect, http.StatusPermanentRedirect)
		}

		type pageData struct {
			LoginURL         string
			LogoutURL        string
			Authenticated    bool
			Version          string
			Categories       []string
			CategorisedItems map[string][]Item
		}

		catItems := make(map[string][]Item)
		cats := index.Categories()
		for _, cat := range cats {
			catItems[cat] = index.ItemsInCategory(cat)
		}

		data := pageData{
			LoginURL:         EndPointLogin,
			LogoutURL:        EndPointLogout,
			Authenticated:    false,
			Version:          Version,
			Categories:       cats,
			CategorisedItems: catItems,
		}

		tplName := "home.gohtml"
		if err := templates.ExecuteTemplate(w, tplName, data); err != nil {
			logger.Err(err).
				Str("tplName", tplName).
				Msg("Failed to execute HTML template")
		}
	})
}

func cryptoRandString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setAuthCookie(w http.ResponseWriter, r *http.Request, name string, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: true,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
	}
	http.SetCookie(w, c)
}

func HandleLogin(server *SqyrrlServer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := server.logger
		logger.Trace().Msg("LoginHandler called")

		w.Header().Add("Cache-Control", "no-cache") // See https://github.com/okta/samples-golang/issues/20

		state, err := cryptoRandString(16)
		if err != nil {
			writeErrorResponse(logger, w, http.StatusInternalServerError)
			return
		}
		setAuthCookie(w, r, "state", state)

		authURL := server.oauth2Config.AuthCodeURL(state)
		logger.Info().
			Str("auth_url", authURL).
			Str("state", state).
			Msg("Redirecting to auth URL")

		http.Redirect(w, r, authURL, http.StatusFound)
	})
}

func HandleAuthCallback(server *SqyrrlServer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := server.logger
		logger.Trace().Msg("AuthCallbackHandler called")

		state, err := r.Cookie("state")
		if err != nil {
			logger.Err(err).Msg("Failed to get state cookie")
			writeErrorResponse(logger, w, http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("state") != state.Value {
			logger.Error().Msg("Response state did not match state cookie")
			writeErrorResponse(logger, w, http.StatusBadRequest)
			return
		}

		// If implementing PKCE, change here to add a verifier
		oauthToken, err := server.oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
		if err != nil {
			logger.Err(err).Msg("Failed to exchange code for token")
			writeErrorResponse(logger, w, http.StatusInternalServerError)
			return
		}

		logger.Info().
			Str("token", oauthToken.AccessToken).
			Msg("Successfully exchanged code for token")

		userInfo, err := server.provider.UserInfo(context.Background(), oauth2.StaticTokenSource(oauthToken))
		if err != nil {
			logger.Err(err).Msg("Failed to get userinfo")
			writeErrorResponse(logger, w, http.StatusInternalServerError)
			return
		}

		resp := struct {
			OAuth2Token *oauth2.Token
			UserInfo    *oidc.UserInfo
		}{oauthToken,
			userInfo,
		}

		data, err := json.MarshalIndent(resp, "", "    ")
		if err != nil {
			logger.Err(err).Msg("Failed to marshal response")
			writeErrorResponse(logger, w, http.StatusInternalServerError)
			return
		}

		w.Write(data)
	})
}

func HandleLogout(logger zerolog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Trace().Msg("LogoutHandler called")

	})
}

func HandleStaticContent(logger zerolog.Logger) http.Handler {
	logger.Trace().Msg("StaticContentHandler called")

	sub := func(dir fs.FS, name string) fs.FS {
		f, err := fs.Sub(dir, name)
		if err != nil {
			logger.Err(err).
				Str("dir", name).
				Msg("Failed to get subdirectory from static content")
		}
		return f
	}
	return http.FileServer(http.FS(sub(staticContentFS, staticContentDir)))
}

func HandleIRODSGet(logger zerolog.Logger, account *types.IRODSAccount) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Trace().Msg("iRODS get handler called")

		var corrID string
		if val := r.Context().Value(correlationIDKey); val != nil {
			corrID = val.(string)
		}

		rodsLogger := logger.With().
			Str("correlation_id", corrID).
			Str("irods", "get").Logger()

		// The path should be clean as it has passed through the ServeMux, but since we're
		// doing a path.Join, clean it before passing it to iRODS
		objPath := path.Clean(path.Join("/", r.URL.Path))
		logger.Debug().Str("path", objPath).Msg("Getting iRODS data object")

		getFileRange(rodsLogger, w, r, account, objPath)
	})
}

// AddRequestLogger adds an HTTP request suiteLogger to the handler chain.
//
// If a correlation ID is present in the request context, it is logged.
func AddRequestLogger(logger zerolog.Logger) HandlerChain {
	return func(next http.Handler) http.Handler {
		lh := hlog.NewHandler(logger)

		ah := hlog.AccessHandler(func(r *http.Request, status, size int, dur time.Duration) {
			var corrID string
			if val := r.Context().Value(correlationIDKey); val != nil {
				corrID = val.(string)
			}

			hlog.FromRequest(r).Info().
				Str("correlation_id", corrID).
				Dur("duration", dur).
				Int("size", size).
				Int("status", status).
				Str("method", r.Method).
				Str("url", r.URL.RequestURI()).
				Str("remote_addr", r.RemoteAddr).
				Str("forwarded_for", r.Header.Get(HeaderForwardedFor)).
				Str("user_agent", r.UserAgent()).
				Msg("Request served")
		})
		return lh(ah(next))
	}
}

// AddCorrelationID adds a correlation ID to the request context and response headers.
func AddCorrelationID(logger zerolog.Logger) HandlerChain {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var corrID string
			if corrID = r.Header.Get(HeaderCorrelationID); corrID == "" {
				corrID = xid.New().String()
				logger.Trace().
					Str("correlation_id", corrID).
					Str("url", r.URL.RequestURI()).
					Msg("Creating a new correlation ID")
				w.Header().Add(HeaderCorrelationID, corrID)
			} else {
				logger.Trace().
					Str("correlation_id", corrID).
					Str("url", r.URL.RequestURI()).
					Msg("Using correlation ID from request")
			}

			ctx := context.WithValue(r.Context(), correlationIDKey, corrID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SanitiseRequestURL sanitises the URL path in the request. All requests pass through
// this as a first step.
func SanitiseRequestURL(logger zerolog.Logger) HandlerChain {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Trace().Str("path", r.URL.Path).Msg("Sanitising URL path")

			// URLs are already cleaned by the Go ServeMux. This is in addition
			dirtyPath := r.URL.Path
			sanPath := userInputPolicy.Sanitize(dirtyPath)
			if sanPath != dirtyPath {
				logger.Warn().
					Str("sanitised_path", sanPath).
					Str("dirty_path", dirtyPath).
					Msg("Path was sanitised")
			}

			url := r.URL
			url.Path = sanPath
			r.URL = url

			next.ServeHTTP(w, r)
		})
	}
}
