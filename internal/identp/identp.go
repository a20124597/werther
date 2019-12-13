/*
Copyright (c) JSC iCore.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
*/

// Package identp is an implementation of [Login and Consent Flow](https://www.ory.sh/docs/hydra/oauth2)
// between ORY Hydra and Werther Identity Provider.
package identp

import (
	"bytes"
	"context"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"werther/internal/hydra"
	"werther/internal/ldapclient"
	auth "werther/pkg/auth"
	emailcli "werther/pkg/emailclient"

	"github.com/i-core/rlog"
	"github.com/justinas/nosurf"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// Version is static css file version.
var Version = "1.0.0"

const (
	loginTmplName         = "login.tmpl"
	forgetTmplName        = "forget.tmpl"
	forgetSuccTmplName    = "forget-succ.tmpl"
	emailNotifyTmplName   = "email-notify.tmpl"
	resetTmplName         = "reset.tmpl"
	resetSuccRediTmplName = "reset-succ-redi.tmpl"
	resetSuccNotiTmplName = "reset-succ-noti.tmpl"

	msgUsernameEmpty   = "用户名不能为空"
	msgUsernameIsEmail = "用户名不能为邮箱"
	msgPassEmpty       = "密码为不能为空"
	msgConnectFailed   = "连接失败"
	msgAuthFailed      = "验证失败"
	msgUnknownUser     = "用户名不存在"
	msgSendEmailFailed = "邮件发送失败"
	msgPassMatchFailed = "密码不匹配"
	msgPassResetFailed = "密码重置失败"
	msgLinkExpired     = "链接过期"
	msgLinkInvalid     = "链接无效"
	msgPassReset       = "密码重置"
	msgPassResetSucc   = "密码重置成功"
	msgResetSuccNotify = "您的密码已重置成功"
	msgAuthSucc        = "校验成功"

	errLinkExpired = "link expired"
)

// Config is a Hydra configuration.
type Config struct {
	HydraURL    string            `envconfig:"hydra_url" required:"true" desc:"an admin URL of ORY Hydra Server"`
	SessionTTL  time.Duration     `envconfig:"session_ttl" default:"24h" desc:"a user session's TTL"`
	ClaimScopes map[string]string `envconfig:"claim_scopes" default:"name:profile,family_name:profile,given_name:profile,email:email,https%3A%2F%2Fgithub.com%2Fi-core%2Fwerther%2Fclaims%2Froles:roles" desc:"a mapping of OpenID Connect claims to scopes (all claims are URL encoded)"`
}

// UserManager is an interface that is used for authentication and providing user's claims.
type UserManager interface {
	authenticator
	oidcClaimsFinder
	ldapBasicOptions
}

// ldapBasicOptions contains basic ldap options.
type ldapBasicOptions interface {
	UserSearch(ctx context.Context, username string, attrs []string) (map[string]interface{}, error)
	PassReset(ctx context.Context, username, newPass string) (bool, error)
}

// authenticator is an interface that is used for a user authentication.
//
// Authenticate returns false if the username or password is invalid.
type authenticator interface {
	Authenticate(ctx context.Context, username, password string) (ok bool, err error)
}

// oidcClaimsFinder is an interface that is used for searching OpenID Connect claims for the given username.
type oidcClaimsFinder interface {
	FindOIDCClaims(ctx context.Context, username string) (map[string]interface{}, error)
}

// TemplateRenderer renders a template with data and writes it to a http.ResponseWriter.
type TemplateRenderer interface {
	GetHTMLTemplate(name string, data interface{}) (*bytes.Buffer, error)
	RenderTemplate(w http.ResponseWriter, name string, data interface{}) error
}

// BaseTmplData record base tmp data.
type BaseTmplData struct {
	CSRFToken    string
	Challenge    string
	URL          string // redirect url
	InvalidForm  bool
	ErrorMessage string
	Version      string
}

// LoginTmplData is a data that is needed for rendering the login page.
type LoginTmplData struct {
	BaseTmplData
	SuccForm bool
}

// ForgetTmplData is a data that is needed for rendering the forget page.
type ForgetTmplData struct {
	BaseTmplData
}

// ResetTmplData is a data that is needed for rendering the reset page.
type ResetTmplData struct {
	BaseTmplData
	UserName string
}

// Handler provides HTTP handlers that implement [Login and Consent Flow](https://www.ory.sh/docs/hydra/oauth2)
// between ORY Hydra and Werther Identity Provider.
type Handler struct {
	Config
	um UserManager
	tr TemplateRenderer
}

// NewHandler creates a new Handler.
//
// The template's renderer must be able to render a template with name "login.tmpl".
// The template is a template of the login page. It receives struct LoginTmplData as template's data.
func NewHandler(cnf Config, um UserManager, tr TemplateRenderer) *Handler {
	return &Handler{Config: cnf, um: um, tr: tr}
}

// AddRoutes registers all required routes for Login & Consent Provider.
func (h *Handler) AddRoutes(apply func(m, p string, h http.Handler, mws ...func(http.Handler) http.Handler)) {
	sessionTTL := int(h.SessionTTL.Seconds())
	apply(http.MethodGet, "/login", newLoginStartHandler(hydra.NewLoginReqDoer(h.HydraURL, 0), h.tr))
	apply(http.MethodPost, "/login", newLoginEndHandler(hydra.NewLoginReqDoer(h.HydraURL, sessionTTL), h.um, h.tr))
	apply(http.MethodGet, "/consent", newConsentHandler(hydra.NewConsentReqDoer(h.HydraURL, sessionTTL), h.um, h.ClaimScopes))
	apply(http.MethodGet, "/logout", newLogoutHandler(hydra.NewLogoutReqDoer(h.HydraURL)))
	apply(http.MethodGet, "/forget", newForgetStartHandler(h.tr))
	apply(http.MethodPost, "/forget", newForgetEndHandler(h.um, h.tr))
	apply(http.MethodGet, "/reset", newResetStartHandler(h.tr))
	apply(http.MethodPost, "/reset", newResetEndHandler(h.um, h.tr))
}

// oa2LoginReqAcceptor is an interface that is used for accepting an OAuth2 login request.
type oa2LoginReqAcceptor interface {
	AcceptLoginRequest(challenge string, remember bool, subject string) (string, error)
}

// oa2LoginReqProcessor is an interface that is used for creating and accepting an OAuth2 login request.
//
// InitiateRequest returns hydra.ErrChallengeNotFound if the OAuth2 provider failed to find the challenge.
// InitiateRequest returns hydra.ErrChallengeExpired if the OAuth2 provider processed the challenge previously.
type oa2LoginReqProcessor interface {
	InitiateRequest(challenge string) (*hydra.ReqInfo, error)
	oa2LoginReqAcceptor
}

func newLoginStartHandler(rproc oa2LoginReqProcessor, tmplRenderer TemplateRenderer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := rlog.FromContext(r.Context()).Sugar()
		challenge := r.URL.Query().Get("login_challenge")
		data := LoginTmplData{
			BaseTmplData: BaseTmplData{
				CSRFToken: nosurf.Token(r),
				Challenge: challenge,
				URL:       strings.TrimPrefix(r.URL.String(), "/"),
				Version:   Version,
			},
		}
		if challenge == "" {
			log.Warn("No login challenge that is needed by the OAuth2 provider")
			renderTmp(w, r, tmplRenderer, &data, false)
			return
		}

		ri, err := rproc.InitiateRequest(challenge)
		if err != nil {
			switch errors.Cause(err) {
			case hydra.ErrChallengeNotFound:
				log.Debugw("Unknown login challenge in the OAuth2 provider", zap.Error(err), "challenge", challenge)
				http.Error(w, "Unknown login challenge", http.StatusBadRequest)
				return
			case hydra.ErrChallengeExpired:
				log.Debugw("Login challenge has been used already in the OAuth2 provider", zap.Error(err), "challenge", challenge)
				http.Error(w, "Login challenge has been used already", http.StatusBadRequest)
				return
			}
			log.Infow("Failed to initiate an OAuth2 login request", zap.Error(err), "challenge", challenge)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		log.Infow("A login request is initiated", "challenge", challenge, "username", ri.Subject)

		if ri.Skip {
			redirectURI, err := rproc.AcceptLoginRequest(challenge, false, ri.Subject)
			if err != nil {
				log.Infow("Failed to accept an OAuth login request", zap.Error(err))
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, redirectURI, http.StatusFound)
			return
		}
		renderTmp(w, r, tmplRenderer, &data, false)
	}
}

func newLoginEndHandler(ra oa2LoginReqAcceptor, auther authenticator, tmplRenderer TemplateRenderer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := rlog.FromContext(r.Context()).Sugar()
		r.ParseForm()
		challenge := r.Form.Get("login_challenge")
		data := LoginTmplData{
			BaseTmplData: BaseTmplData{
				CSRFToken: nosurf.Token(r),
				Challenge: challenge,
				URL:       r.URL.String(),
				Version:   Version,
			},
		}
		// check whether the form parameter is empty.
		username, password := r.Form.Get("username"), r.Form.Get("password")
		err := validUsername(username)
		switch {
		case err != nil:
			data.ErrorMessage = err.Error()
		case password == "":
			data.ErrorMessage = msgPassEmpty
		}
		if data.ErrorMessage != "" {
			renderTmp(w, r, tmplRenderer, &data, true)
			return
		}

		// check whether the pasword is valid.
		_, err = auther.Authenticate(r.Context(), username, password)
		switch {
		case err == ldapclient.ErrConnectionTimeout:
			data.ErrorMessage = msgConnectFailed
		case err == ldapclient.ErrUnknownUsername:
			data.ErrorMessage = msgUnknownUser
		case err != nil:
			data.ErrorMessage = msgAuthFailed
		}
		if err != nil {
			renderTmp(w, r, tmplRenderer, &data, true)
			return
		}

		log.Infow("The username is authenticated", "challenge", challenge, "username", username)
		if challenge == "" {
			data.SuccForm = true
			data.ErrorMessage = msgAuthSucc
			log.Warn("No login challenge that is needed by the OAuth2 provider")
			renderTmp(w, r, tmplRenderer, &data, false)
			return
		}

		remember := r.Form.Get("remember") != ""
		redirectTo, err := ra.AcceptLoginRequest(challenge, remember, username)
		if err != nil {
			data.ErrorMessage = msgConnectFailed
			renderTmp(w, r, tmplRenderer, &data, true)
			return
		}
		http.Redirect(w, r, redirectTo, http.StatusFound)
	}
}

// oa2ConsentReqAcceptor is an interface that is used for creating and accepting an OAuth2 consent request.
//
// InitiateRequest returns hydra.ErrChallengeNotFound if the OAuth2 provider failed to find the challenge.
// InitiateRequest returns hydra.ErrChallengeExpired if the OAuth2 provider processed the challenge previously.
type oa2ConsentReqProcessor interface {
	InitiateRequest(challenge string) (*hydra.ReqInfo, error)
	AcceptConsentRequest(challenge string, remember bool, grantScope []string, idToken interface{}) (string, error)
}

func newConsentHandler(rproc oa2ConsentReqProcessor, cfinder oidcClaimsFinder, claimScopes map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := rlog.FromContext(r.Context()).Sugar()

		challenge := r.URL.Query().Get("consent_challenge")
		if challenge == "" {
			log.Debug("No consent challenge that is needed by the OAuth2 provider")
			http.Error(w, "No consent challenge", http.StatusBadRequest)
			return
		}

		ri, err := rproc.InitiateRequest(challenge)
		if err != nil {
			switch errors.Cause(err) {
			case hydra.ErrChallengeNotFound:
				log.Debugw("Unknown consent challenge in the OAuth2 provider", zap.Error(err), "challenge", challenge)
				http.Error(w, "Unknown consent challenge", http.StatusBadRequest)
				return
			case hydra.ErrChallengeExpired:
				log.Debugw("Consent challenge has been used already in the OAuth2 provider", zap.Error(err), "challenge", challenge)
				http.Error(w, "Consent challenge has been used already", http.StatusBadRequest)
				return
			}
			log.Infow("Failed to send an OAuth2 consent request", zap.Error(err), "challenge", challenge)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		log.Infow("A consent request is initiated", "challenge", challenge, "username", ri.Subject)

		claims, err := cfinder.FindOIDCClaims(r.Context(), ri.Subject)
		if err != nil {
			log.Infow("Failed to find user's OIDC claims", zap.Error(err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		log.Debugw("Found user's OIDC claims", "claims", claims)

		// Remove claims that are not in the requested scopes.
		for claim := range claims {
			var found bool
			// We need to escape a claim due to ClaimScopes' keys contain URL encoded claims.
			// It is because of config option's format compatibility.
			if scope, ok := claimScopes[url.QueryEscape(claim)]; ok {
				for _, rscope := range ri.RequestedScopes {
					if rscope == scope {
						found = true
						break
					}
				}
			}
			if !found {
				delete(claims, claim)
				log.Debugw("Deleted the OIDC claim because it's not in requested scopes", "claim", claim)
			}
		}
		redirectTo, err := rproc.AcceptConsentRequest(challenge, !ri.Skip, ri.RequestedScopes, claims)
		if err != nil {
			log.Infow("Failed to accept a consent request to the OAuth2 provider", zap.Error(err), "scopes", ri.RequestedScopes, "claims", claims)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		log.Debugw("Accepted the consent request to the OAuth2 provider", "scopes", ri.RequestedScopes, "claims", claims)
		http.Redirect(w, r, redirectTo, http.StatusFound)
	}
}

// oa2LogoutReqProcessor is an interface that is used for creating and accepting an OAuth2 logout request.
//
// InitiateRequest returns hydra.ErrChallengeNotFound if the OAuth2 provider failed to find the challenge.
type oa2LogoutReqProcessor interface {
	InitiateRequest(challenge string) (*hydra.ReqInfo, error)
	AcceptLogoutRequest(challenge string) (string, error)
}

func newLogoutHandler(rproc oa2LogoutReqProcessor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := rlog.FromContext(r.Context()).Sugar()

		challenge := r.URL.Query().Get("logout_challenge")
		if challenge == "" {
			log.Debug("No logout challenge that is needed by the OAuth2 provider")
			http.Error(w, "No logout challenge", http.StatusBadRequest)
			return
		}

		ri, err := rproc.InitiateRequest(challenge)
		if err != nil {
			switch errors.Cause(err) {
			case hydra.ErrChallengeNotFound:
				log.Debugw("Unknown logout challenge in the OAuth2 provider", zap.Error(err), "challenge", challenge)
				http.Error(w, "Unknown logout challenge", http.StatusBadRequest)
				return
			}
			log.Infow("Failed to send an OAuth2 logout request", zap.Error(err), "challenge", challenge)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		log.Infow("A logout request is initiated", "challenge", challenge, "username", ri.Subject)

		redirectTo, err := rproc.AcceptLogoutRequest(challenge)
		if err != nil {
			log.Infow("Failed to accept the logout request to the OAuth2 provider", zap.Error(err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		log.Debugw("Accepted the logout request to the OAuth2 provider")
		http.Redirect(w, r, redirectTo, http.StatusFound)
	}
}

func newForgetStartHandler(tmplRenderer TemplateRenderer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		challenge := r.URL.Query().Get("login_challenge")
		data := ForgetTmplData{
			BaseTmplData{
				CSRFToken: nosurf.Token(r),
				Challenge: challenge,
				URL:       strings.TrimPrefix(r.URL.String(), "/"),
				Version:   Version,
			},
		}
		renderTmp(w, r, tmplRenderer, &data, false)
	}
}

func newForgetEndHandler(um UserManager, tmplRenderer TemplateRenderer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := rlog.FromContext(r.Context()).Sugar()
		r.ParseForm()
		challenge := r.Form.Get("login_challenge")
		data := ForgetTmplData{
			BaseTmplData{
				CSRFToken: nosurf.Token(r),
				Challenge: challenge,
				URL:       r.URL.String(),
				Version:   Version,
			},
		}
		// check whether the form username input is empty.
		username := r.Form.Get("username")
		if err := validUsername(username); err != nil {
			data.ErrorMessage = err.Error()
			renderTmp(w, r, tmplRenderer, &data, true)
			return
		}

		// get user detail info from ldap.
		details, err := um.UserSearch(r.Context(), username, []string{"dn", "mail"})
		switch {
		case err == ldapclient.ErrConnectionTimeout:
			data.ErrorMessage = msgConnectFailed
		case err != nil:
			data.ErrorMessage = msgUnknownUser
		}
		if err != nil {
			log.Error("Failed to search user ", username, err.Error())
			renderTmp(w, r, tmplRenderer, &data, true)
			return
		}

		// send email for resetting password link to user.
		toEmail, ok := details["mail"]
		if !ok {
			data.ErrorMessage = msgSendEmailFailed
			log.Error("Failed to send email for user ", username)
			renderTmp(w, r, tmplRenderer, &data, true)
			return
		}
		others := make(map[string]string)
		if challenge != "" {
			others["login_challenge"] = challenge
		}
		others["username"] = username
		schema := getRequestScheme(r)
		hostURL := getRequestHost(r)
		baseResetURL := schema + "://" + hostURL + "/auth/reset"
		resetURL, err := GenerateResetURL(baseResetURL, username, others)
		if err != nil {
			data.ErrorMessage = msgSendEmailFailed
			renderTmp(w, r, tmplRenderer, &data, true)
			return
		}
		err = SendEmail(toEmail.(string), resetURL, tmplRenderer)
		if err != nil {
			data.ErrorMessage = msgSendEmailFailed
			log.Error("Failed to send email for user ", username, zap.Error(err))
			renderTmp(w, r, tmplRenderer, &data, true)
			return
		}
		log.Infow("send email succes for user " + username)

		// finish forget password deal proccess, and show redirect page.
		forgetSucc := struct {
			Email   string
			Version string
		}{
			Email:   toEmail.(string),
			Version: Version,
		}
		render(w, r, tmplRenderer, forgetSuccTmplName, forgetSucc)
	}
}

func newResetStartHandler(tmplRenderer TemplateRenderer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := validResetURL(w, r); err != nil {
			return
		}
		challenge := r.URL.Query().Get("login_challenge")
		username := r.URL.Query().Get("username")
		data := ResetTmplData{
			BaseTmplData: BaseTmplData{
				CSRFToken: nosurf.Token(r),
				Challenge: challenge,
				URL:       strings.TrimPrefix(r.URL.String(), "/"),
				Version:   Version,
			},
			UserName: username,
		}
		renderTmp(w, r, tmplRenderer, &data, false)
	}
}

func newResetEndHandler(um UserManager, tmplRenderer TemplateRenderer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := rlog.FromContext(r.Context()).Sugar()
		// verify whether reset url is valid.
		if err := validResetURL(w, r); err != nil {
			return
		}

		r.ParseForm()
		challenge := r.Form.Get("login_challenge")
		username := r.Form.Get("username")
		password := r.Form.Get("password")
		rePassword := r.Form.Get("re-password")
		data := ResetTmplData{
			BaseTmplData: BaseTmplData{
				CSRFToken: nosurf.Token(r),
				Challenge: challenge,
				URL:       strings.TrimPrefix(r.URL.String(), "/"),
				Version:   Version,
			},
			UserName: username,
		}

		// Verify password consistency.
		if password != rePassword {
			data.ErrorMessage = msgPassMatchFailed
			renderTmp(w, r, tmplRenderer, &data, true)
			return
		}

		// reset user's password.
		_, err := um.PassReset(r.Context(), username, password)
		if err != nil {
			data.ErrorMessage = msgPassResetFailed
			renderTmp(w, r, tmplRenderer, &data, true)
			return
		}
		log.Infow("Success reset password for user " + username)

		// If challenge is not empty, then return to login page.
		if challenge != "" {
			redirectTo := "/auth/login?login_challenge=" + challenge
			data := struct {
				Title        string
				InternalTime int
				JumpURL      template.URL
				Version      string
			}{
				Title:        msgPassResetSucc,
				InternalTime: 5,
				JumpURL:      template.URL(redirectTo),
				Version:      Version,
			}
			render(w, r, tmplRenderer, resetSuccRediTmplName, data)
			return
		}

		// otherwise just show page for notify reset success.
		dataNotify := struct {
			Title         string
			NotifyMessage string
			Version       string
		}{
			Title:         msgPassResetSucc,
			NotifyMessage: username + ":" + msgResetSuccNotify,
			Version:       Version,
		}
		render(w, r, tmplRenderer, resetSuccNotiTmplName, dataNotify)
	}
}

// SendEmail send reset pass link to destination email.
func SendEmail(toEmail, resetURL string, tmplRenderer TemplateRenderer) error {
	data := struct {
		ResetURL string
		HrefURL  template.URL
	}{
		ResetURL: resetURL,
		HrefURL:  template.URL(resetURL),
	}
	contentBuffer, err := tmplRenderer.GetHTMLTemplate(emailNotifyTmplName, data)
	if err != nil {
		return err
	}
	emailCli := emailcli.NewEmailCli()
	err = emailCli.DialServer()
	if err != nil {
		return err
	}
	emailMess := &emailcli.EmailMessage{
		Subject: msgPassReset,
		Toers:   toEmail,
		Content: contentBuffer.String(),
	}
	err = emailCli.SendEmail(emailMess)
	if err != nil {
		return err
	}
	return nil
}

// GenerateResetURL generate reset url and send to user.
func GenerateResetURL(baseURL, username string, others map[string]string) (string, error) {
	url, err := auth.GetSignURL(baseURL, username, others)
	if err != nil {
		return "", err
	}
	return url, nil
}

// renderTmp render tmplate to html.
func renderTmp(w http.ResponseWriter, r *http.Request, tmplRenderer TemplateRenderer,
	data interface{}, status bool) {
	var renderTmpName string
	switch v := data.(type) {
	case *LoginTmplData:
		renderTmpName = loginTmplName
		v.InvalidForm = status
		render(w, r, tmplRenderer, renderTmpName, v)
	case *ForgetTmplData:
		renderTmpName = forgetTmplName
		v.InvalidForm = status
		render(w, r, tmplRenderer, renderTmpName, v)
	case *ResetTmplData:
		renderTmpName = resetTmplName
		v.InvalidForm = status
		render(w, r, tmplRenderer, renderTmpName, v)
	}
}

// render template to html.
func render(w http.ResponseWriter, r *http.Request, tmplRenderer TemplateRenderer,
	renderTmpName string, data interface{}) {
	log := rlog.FromContext(r.Context()).Sugar()
	if err := tmplRenderer.RenderTemplate(w, renderTmpName, data); err != nil {
		log.Infow("Failed to render "+renderTmpName, zap.Error(err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
	return
}

func getRequestHost(req *http.Request) string {
	if host := req.Header.Get("X-Forwarded-Host"); host != "" {
		return host
	}
	return req.Host
}

func getRequestScheme(req *http.Request) string {
	var reqProto string
	if proto := req.Header.Get("X-Forwarded-Proto"); proto != "" {
		// https
		reqProto = proto
	} else {
		// HTTP/1.1
		reqProto = req.Proto
	}
	if reqProto == "https" {
		return "https"
	} else {
		return "http"
	}
}

func validUsername(username string) error {
	// emailRexPattern is email regular expression.
	emailRexPattern := `^[0-9a-z][_.0-9a-z-]{0,31}@([0-9a-z][0-9a-z-]{0,30}[0-9a-z]\.){1,4}[a-z]{2,4}$`
	reg := regexp.MustCompile(emailRexPattern)
	switch {
	case username == "":
		return errors.New(msgUsernameEmpty)
	case reg.MatchString(username):
		return errors.New(msgUsernameIsEmail)
	}
	return nil
}

func validResetURL(w http.ResponseWriter, r *http.Request) error {
	_, err := auth.VerifySign(r.RequestURI)
	if err != nil {
		if err.Error() == errLinkExpired {
			http.Error(w, msgLinkExpired, http.StatusBadRequest)
			return err
		}
		http.Error(w, msgLinkInvalid, http.StatusBadRequest)
		return err
	}
	return nil
}
