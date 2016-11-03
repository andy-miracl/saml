package samlidp

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml"
	"github.com/miracl/maas-sdk-go"
	"github.com/zenazn/goji/web"
)

var sessionMaxAge = time.Hour

// GetSession returns the *Session for this request.
//
// If the remote user has specified a username and password in the request
// then it is validated against the user database. If valid it sets a
// cookie and returns the newly created session object.
//
// If the remote user has specified invalid credentials then a login form
// is returned with an English-language toast telling the user their
// password was invalid.
//
// If a session cookie already exists and represents a valid session,
// then the session is returned
//
// If neither credentials nor a valid session cookie exist, this function
// sends a login form and returns nil.
func (s *Server) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	mc, err := s.NewMfaClient()

	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}

	query := r.URL.Query()
	code := query.Get("code")

	if code != "" {
		// we have a valid response from MFA

		accessToken, jwt, err := mc.ValidateAuth(code)
		if err != nil {
			// if authorization code is invalid, redirect to index
			http.Redirect(w, r, "/", 302)
			return nil
		}

		// dump our claims for debugging
		claims, _ := jwt.Claims()
		fmt.Printf("Access token: %v\n", accessToken)
		fmt.Printf("JTW payload: %+v\n", claims)

		// Retrieve useir info from oidc server
		userInfo, err := mc.GetUserUnfo(accessToken)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return nil
		}
		fmt.Printf("userInfo: %s,%s\n", userInfo.UserID, userInfo.Email)

		// find our user in our store (this eventually will be LDAP)
		user := User{}
		key := fmt.Sprintf("/users/%s", userInfo.UserID)
		fmt.Printf("key: %+v\n", key)
		if err := s.Store.Get(key, &user); err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return nil
		}

		// create a new session for this authenticated and authorised user
		session := &saml.Session{
			ID:             base64.StdEncoding.EncodeToString(randomBytes(32)),
			CreateTime:     saml.TimeNow(),
			ExpireTime:     saml.TimeNow().Add(sessionMaxAge),
			Index:          hex.EncodeToString(randomBytes(32)),
			UserName:       user.Name,
			Groups:         user.Groups[:],
			UserEmail:      user.Email,
			UserCommonName: user.CommonName,
			UserSurname:    user.Surname,
			UserGivenName:  user.GivenName,
		}

		// save the session
		if err := s.Store.Put(fmt.Sprintf("/sessions/%s", session.ID), &session); err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return nil
		}

		// set the session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    session.ID,
			MaxAge:   int(sessionMaxAge.Seconds()),
			HttpOnly: false,
			Path:     "/",
		})

		// redirect back to our  sso endpoint (ultimately we can avoid this extra redirection)
		url := query.Get("state")
		if url == "" {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return nil
		}
		fmt.Printf("redirecting to sso: %v\n", url)
		http.Redirect(w, r, url, http.StatusFound)

		return session
	}

	// this request does not represent a  valid response from MFA
	if sessionCookie, err := r.Cookie("session"); err == nil {
		session := &saml.Session{}
		if err := s.Store.Get(fmt.Sprintf("/sessions/%s", sessionCookie.Value), session); err != nil {
			if err == ErrNotFound {
				s.sendLoginForm(mc, w, r, req)
				return nil
			}
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return nil
		}

		if saml.TimeNow().After(session.ExpireTime) {
			s.sendLoginForm(mc, w, r, req)
			return nil
		}
		return session
	}

	s.sendLoginForm(mc, w, r, req)
	return nil
}

// sendLoginForm produces a form which requests a username and password and directs the user
// back to the IDP authorize URL to restart the SAML login flow, this time establishing a
// session based on the credentials that were provided.
func (s *Server) sendLoginForm(mc maas.Client, w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) {

	// deflate the SAMLRequest and encode it
	var buffer bytes.Buffer
	writer, _ := flate.NewWriter(&buffer, flate.BestCompression)
	writer.Write(req.RequestBuffer)
	writer.Close()
	samlRequest := base64.StdEncoding.EncodeToString(buffer.Bytes())
	fmt.Printf("SAMLRequest: %v\n", samlRequest)

	// construct a url to callback to our sso endpoint
	url, _ := url.Parse(req.IDP.SSOURL)
	query := url.Query()
	query.Add("SAMLRequest", samlRequest)
	query.Add("RelayState", req.RelayState)
	url.RawQuery = query.Encode()

	authURL, err := mc.GetAuthRequestURL(url.String())
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleLogin handles the `POST /login` and `GET /login` forms. If credentials are present
// in the request body, then they are validated. For valid credentials, the response is a
// 200 OK and the JSON session object. For invalid credentials, the HTML login prompt form
// is sent.
func (s *Server) HandleLogin(c web.C, w http.ResponseWriter, r *http.Request) {
	session := s.GetSession(w, r, &saml.IdpAuthnRequest{IDP: &s.IDP})
	if session == nil {
		return
	}
	json.NewEncoder(w).Encode(session)
}

// HandleListSessions handles the `GET /sessions/` request and responds with a JSON formatted list
// of session names.
func (s *Server) HandleListSessions(c web.C, w http.ResponseWriter, r *http.Request) {
	sessions, err := s.Store.List("/sessions/")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(struct {
		Sessions []string `json:"sessions"`
	}{Sessions: sessions})
}

// HandleGetSession handles the `GET /sessions/:id` request and responds with the session
// object in JSON format.
func (s *Server) HandleGetSession(c web.C, w http.ResponseWriter, r *http.Request) {
	session := saml.Session{}
	err := s.Store.Get(fmt.Sprintf("/sessions/%s", c.URLParams["id"]), &session)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(session)
}

// HandleDeleteSession handles the `DELETE /sessions/:id` request. It invalidates the
// specified session.
func (s *Server) HandleDeleteSession(c web.C, w http.ResponseWriter, r *http.Request) {
	err := s.Store.Delete(fmt.Sprintf("/sessions/%s", c.URLParams["id"]))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
