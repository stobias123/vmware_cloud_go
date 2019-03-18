package vmware_cloud_go

import (
"bytes"
"encoding/json"
"errors"
"fmt"
"io"
"io/ioutil"
"net/http"
"net/url"
"os"
"strings"
)

const ClientUserAgentString = "VMWare Cloud Go SDK v2.0.8"
const defaultVMCUrl = "https://vmc.vmware.com/vmc/api"
const authEndpoint = "https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize"

// APIClient references an api token and an http endpoint
type APIClient struct {
	Auth       *AuthResponse
	Endpoint   string
	HttpClient *http.Client
}

// APIReq struct holds data for runRequest method to operate http request on
type APIReq struct {
	Method         string
	Path           string
	PostObj        interface{}
	Payload        io.Reader
	ResponseObj    interface{}
	WantedStatus   int
	ResponseString string
	DontUnmarsahal bool
}

// AuthResponse object - holds token info
type AuthResponse struct {
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int `json:"expires_in"`
	Scope        string `json:"scope"`
	Token        string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// NewClient returns a new api client
func NewClient(refreshToken, endpoint string) *APIClient {

	c := &APIClient{
		Auth: &AuthResponse{},
		Endpoint:   strings.TrimRight(endpoint, "/"),
		HttpClient: http.DefaultClient,
	}
	c.getAuthToken(refreshToken)
	return c
}

// NewClientFromEnv creates a new client from environment variables
func NewClientFromEnv() (*APIClient, error) {
	refreshToken := os.Getenv("VMC_REFRESH_TOKEN")
	if refreshToken == "" {
		return nil, errors.New("Missing refreshToken env in VMC_REFRESH_TOKEN")
	}
	endpoint := os.Getenv("VMC_API_URL")
	if endpoint == "" {
		endpoint = defaultVMCUrl
	}

	return NewClient(refreshToken, endpoint), nil
}

func (c *APIClient) getAuthToken(refreshToken string) error {

	data := url.Values{}
	data.Set("refresh_token", refreshToken)

	u, _ := url.ParseRequestURI(authEndpoint)
	urlStr := u.String()

	client := &http.Client{}
	r, _ := http.NewRequest("POST", urlStr, strings.NewReader(data.Encode())) // URL-encoded payload
	r.Header.Add("Accept", "application/json")
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	//r.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

	resp, _ := client.Do(r)
	if resp.StatusCode != 200 {
		return fmt.Errorf("Error - Non 200 Response code: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return err
	}

	return json.Unmarshal(body, c.Auth)
}

// runRequest performs HTTP request, takes APIReq object
func (c *APIClient) runRequest(req *APIReq) error {
	// If method is POST and postObjNeedsEncoding, encode data object and set up payload
	if req.Method == "POST" && req.Payload == nil {
		data, err := json.Marshal(req.PostObj)
		if err != nil {
			return err
		}
		req.Payload = bytes.NewBuffer(data)
	}

	// If path is not fully qualified URL, then prepend with endpoint URL
	if req.Path[0:4] != "http" {
		req.Path = c.Endpoint + req.Path
	}

	// Set up new HTTP request
	httpReq, err := http.NewRequest(req.Method, req.Path, req.Payload)
	if err != nil {
		return err
	}
	httpReq.Header.Set("csp-auth-token", c.Auth.Token)
	httpReq.Header.Set("User-Agent", ClientUserAgentString)
	httpReq.Header.Set("Content-Type", "application/json")

	// Run HTTP request, catching response
	resp, err := c.HttpClient.Do(httpReq)
	if err != nil {
		return err
	}

	// Check Status Code versus what the caller wanted, error if not correct
	if req.WantedStatus != resp.StatusCode {
		body, _ := ioutil.ReadAll(resp.Body)
		err = fmt.Errorf("Incorrect status code returned: %d, Status: %s\n%s", resp.StatusCode, resp.Status, string(body))
		return err
	}

	// If DELETE operation, return
	if req.Method == "DELETE" || req.ResponseObj == nil {
		return nil
	}

	// Store response from remote server, if not a delete operation
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	req.ResponseString = string(body)

	if req.DontUnmarsahal {
		return err
	}

	// Unmarshal response into ResponseObj struct, return ResponseObj and error, if there is one
	return json.Unmarshal(body, req.ResponseObj)
}
