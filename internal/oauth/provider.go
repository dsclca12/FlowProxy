package oauth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

// UserInfo represents authenticated user information from an OAuth provider.
type UserInfo struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Subject string `json:"sub"`
}

// Provider defines the interface for OAuth 2.0 / OIDC providers.
type Provider interface {
	// Name returns the provider name.
	Name() string
	// AuthURL returns the authorization URL with the state parameter.
	AuthURL(state string) string
	// Exchange exchanges the authorization code for a token.
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
	// UserInfo retrieves user information using the access token.
	UserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error)
}

// ProviderConfig holds the configuration for creating a provider.
type ProviderConfig struct {
	Type         ProviderType
	ClientID     string
	ClientSecret string
	Scopes       []string
	RedirectURL  string
	// OIDC-specific
	IssuerURL string
	// Generic OAuth2
	AuthURL     string
	TokenURL    string
	UserInfoURL string
}

// NewProvider creates an OAuth provider based on the configuration.
func NewProvider(cfg ProviderConfig) (Provider, error) {
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, errors.New("oauth client id is required")
	}
	if strings.TrimSpace(cfg.ClientSecret) == "" {
		return nil, errors.New("oauth client secret is required")
	}
	if strings.TrimSpace(cfg.RedirectURL) == "" {
		return nil, errors.New("oauth redirect url is required")
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	switch cfg.Type {
	case ProviderGoogle:
		return newGoogleProvider(cfg.ClientID, cfg.ClientSecret, cfg.RedirectURL, scopes), nil
	case ProviderGitHub:
		return newGitHubProvider(cfg.ClientID, cfg.ClientSecret, cfg.RedirectURL, scopes), nil
	case ProviderOIDC:
		return newOIDCProvider(cfg.ClientID, cfg.ClientSecret, cfg.RedirectURL, scopes, cfg.IssuerURL)
	case ProviderGeneric:
		return newGenericProvider(cfg.ClientID, cfg.ClientSecret, cfg.RedirectURL, scopes,
			cfg.AuthURL, cfg.TokenURL, cfg.UserInfoURL), nil
	default:
		return nil, fmt.Errorf("unsupported oauth provider type: %s", cfg.Type)
	}
}

// ---- Google Provider ----

type googleProvider struct {
	config *oauth2.Config
}

func newGoogleProvider(clientID, clientSecret, redirectURL string, scopes []string) *googleProvider {
	return &googleProvider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       scopes,
			Endpoint:     endpoints.Google,
		},
	}
}

func (p *googleProvider) Name() string { return "google" }

func (p *googleProvider) AuthURL(state string) string {
	return p.config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
}

func (p *googleProvider) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.config.Exchange(ctx, code)
}

func (p *googleProvider) UserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	client := p.config.Client(ctx, token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v3/userinfo", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var info struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}
	return &UserInfo{
		ID:      info.Sub,
		Email:   info.Email,
		Name:    info.Name,
		Subject: info.Sub,
	}, nil
}

// ---- GitHub Provider ----

type gitHubProvider struct {
	config *oauth2.Config
}

func newGitHubProvider(clientID, clientSecret, redirectURL string, scopes []string) *gitHubProvider {
	return &gitHubProvider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       scopes,
			Endpoint:     endpoints.GitHub,
		},
	}
}

func (p *gitHubProvider) Name() string { return "github" }

func (p *gitHubProvider) AuthURL(state string) string {
	return p.config.AuthCodeURL(state)
}

func (p *gitHubProvider) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.config.Exchange(ctx, code)
}

func (p *gitHubProvider) UserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	client := p.config.Client(ctx, token)

	// Get user email
	emailReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	emailResp, err := client.Do(emailReq)
	if err != nil {
		return nil, err
	}
	defer emailResp.Body.Close()

	type ghEmail struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	var emails []ghEmail
	if err := json.NewDecoder(emailResp.Body).Decode(&emails); err != nil {
		return nil, err
	}

	primaryEmail := ""
	for _, e := range emails {
		if e.Primary && e.Verified {
			primaryEmail = e.Email
			break
		}
	}

	// Get user info
	userReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	userResp, err := client.Do(userReq)
	if err != nil {
		return nil, err
	}
	defer userResp.Body.Close()

	var ghUser struct {
		ID    int    `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(userResp.Body).Decode(&ghUser); err != nil {
		return nil, err
	}

	if primaryEmail == "" {
		primaryEmail = ghUser.Email
	}

	return &UserInfo{
		ID:      fmt.Sprintf("%d", ghUser.ID),
		Email:   primaryEmail,
		Name:    ghUser.Name,
		Subject: fmt.Sprintf("%d", ghUser.ID),
	}, nil
}

// ---- Generic OAuth2 Provider ----

type genericProvider struct {
	config      *oauth2.Config
	userInfoURL string
}

func newGenericProvider(clientID, clientSecret, redirectURL string, scopes []string, authURL, tokenURL, userInfoURL string) *genericProvider {
	return &genericProvider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authURL,
				TokenURL: tokenURL,
			},
		},
		userInfoURL: userInfoURL,
	}
}

func (p *genericProvider) Name() string { return "generic" }

func (p *genericProvider) AuthURL(state string) string {
	return p.config.AuthCodeURL(state)
}

func (p *genericProvider) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.config.Exchange(ctx, code)
}

func (p *genericProvider) UserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	client := p.config.Client(ctx, token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Try standard fields
	var stdInfo struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		PreferredName string `json:"preferred_username"`
	}
	if err := json.Unmarshal(body, &stdInfo); err == nil && stdInfo.Sub != "" {
		return &UserInfo{
			ID:      stdInfo.Sub,
			Email:   stdInfo.Email,
			Name:    stdInfo.Name,
			Subject: stdInfo.Sub,
		}, nil
	}

	// Fallback: parse flat JSON for id
	var flat map[string]interface{}
	if err := json.Unmarshal(body, &flat); err != nil {
		return nil, errors.New("cannot parse user info response")
	}

	info := &UserInfo{}
	if id, ok := flat["id"].(string); ok {
		info.ID = id
	} else if id, ok := flat["id"].(float64); ok {
		info.ID = fmt.Sprintf("%.0f", id)
	}
	if email, ok := flat["email"].(string); ok {
		info.Email = email
	}
	if name, ok := flat["name"].(string); ok {
		info.Name = name
	}
	if sub, ok := flat["sub"].(string); ok {
		info.Subject = sub
	} else {
		info.Subject = info.ID
	}

	if info.ID == "" {
		return nil, errors.New("cannot extract user id from user info response")
	}
	return info, nil
}

// ---- OIDC Provider ----

type oidcProvider struct {
	config      *oauth2.Config
	userInfoURL string
	httpClient  *http.Client
}

func newOIDCProvider(clientID, clientSecret, redirectURL string, scopes []string, issuerURL string) (*oidcProvider, error) {
	issuerURL = strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	if issuerURL == "" {
		return nil, errors.New("oidc issuer url is required")
	}

	// Discover OIDC configuration
	discoveryURL := issuerURL + "/.well-known/openid-configuration"
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	resp, err := httpClient.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc discovery returned status %d", resp.StatusCode)
	}

	var discovery struct {
		AuthURL     string `json:"authorization_endpoint"`
		TokenURL    string `json:"token_endpoint"`
		UserInfoURL string `json:"userinfo_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, fmt.Errorf("oidc discovery parse failed: %w", err)
	}

	if discovery.AuthURL == "" || discovery.TokenURL == "" {
		return nil, errors.New("oidc discovery missing required endpoints")
	}

	return &oidcProvider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  discovery.AuthURL,
				TokenURL: discovery.TokenURL,
			},
		},
		userInfoURL: discovery.UserInfoURL,
		httpClient:  httpClient,
	}, nil
}

func (p *oidcProvider) Name() string { return "oidc" }

func (p *oidcProvider) AuthURL(state string) string {
	return p.config.AuthCodeURL(state)
}

func (p *oidcProvider) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.config.Exchange(ctx, code)
}

func (p *oidcProvider) UserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	if p.userInfoURL == "" {
		return nil, errors.New("oidc provider has no userinfo endpoint")
	}

	client := p.config.Client(ctx, token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var info UserInfo
	var raw map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}

	if sub, ok := raw["sub"].(string); ok {
		info.Subject = sub
		info.ID = sub
	}
	if email, ok := raw["email"].(string); ok {
		info.Email = email
	}
	if name, ok := raw["name"].(string); ok {
		info.Name = name
	} else if preferredName, ok := raw["preferred_username"].(string); ok {
		info.Name = preferredName
	}

	if info.ID == "" {
		return nil, errors.New("oidc userinfo response missing sub claim")
	}

	return &info, nil
}
