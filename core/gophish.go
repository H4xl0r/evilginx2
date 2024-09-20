package core

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-resty/resty/v2"
)

type GoPhish struct {
	AdminUrl    *url.URL
	ApiKey      string
	InsecureTLS bool
}

type ResultRequest struct {
	Target       string       `json:"-"`
	Action       string       `json:"-"`
	Type         string       `json:"-"`
	EventDetails EventDetails `json:"-"`
}

// EventDetails is a struct that wraps common attributes we want to store
// in an event
type EventDetails struct {
	Payload url.Values        `json:"payload"`
	Browser map[string]string `json:"browser"`
}

func NewGoPhish() *GoPhish {
	return &GoPhish{}
}

func (o *GoPhish) Setup(adminUrl string, apiKey string, insecureTLS bool) error {

	var u *url.URL = nil
	var err error
	if adminUrl != "" {
		u, err = url.ParseRequestURI(adminUrl)
		if err != nil {
			return err
		}
	}
	o.AdminUrl = u
	o.ApiKey = apiKey
	o.InsecureTLS = insecureTLS
	return nil
}

func (o *GoPhish) Test() error {
	err := o.validateSetup()
	if err != nil {
		return err
	}

	var reqUrl url.URL = *o.AdminUrl
	reqUrl.Path = "/api/pages"
	return o.sendWebhookRequest(reqUrl.String(), nil)
}

func (o *GoPhish) ReportGophish(resultRequest ResultRequest) error {
	err := o.validateSetup()
	if err != nil {
		return err
	}

	// Marshal the resultRequest struct to JSON
	content, err := json.Marshal(resultRequest)
	if err != nil {
		return err
	}

	var reqUrl url.URL = *o.AdminUrl
	reqUrl.Path = "/webhook/result"
	return o.sendWebhookRequest(reqUrl.String(), content)
}

func (o *GoPhish) sendWebhookRequest(reqUrl string, content []byte) error {
	cl := resty.New()

	cl.SetTLSClientConfig(&tls.Config{
		InsecureSkipVerify: o.InsecureTLS,
	})

	resp, err := cl.R().
		SetHeader("Content-Type", "application/json").
		SetAuthToken(o.ApiKey).
		SetBody(content).
		Post(reqUrl)

	// Handle the response
	if err != nil {
		return err
	}

	switch resp.StatusCode() {
	case http.StatusOK, http.StatusAccepted:
		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid api key")
	default:
		return fmt.Errorf("status: %d", resp.StatusCode())
	}
}

func (o *GoPhish) validateSetup() error {
	if o.AdminUrl == nil {
		return fmt.Errorf("admin url is not set")
	}
	if o.ApiKey == "" {
		return fmt.Errorf("api key is not set")
	}
	return nil
}
