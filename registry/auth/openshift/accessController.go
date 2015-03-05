package openshift

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	log "github.com/Sirupsen/logrus"
	ctxu "github.com/docker/distribution/context"
	"github.com/docker/distribution/registry/auth"
	"golang.org/x/net/context"

	authorizationapi "github.com/openshift/origin/pkg/authorization/api"
)

type AccessController struct {
	OpenShiftAddr       string
	OpenShiftApiVersion string
	Client              *http.Client
}

type authChallenge struct {
	err error
}

type OpenShiftAccess struct {
	Namespace   string
	ImageRepo   string
	Verb        string
	BearerToken string
}

var _ auth.AccessController = &AccessController{}
var _ auth.Challenge = &authChallenge{}

// Errors used and exported by this package.
var (
	ErrTokenRequired          = errors.New("authorization header with basic token required")
	ErrTokenInvalid           = errors.New("failed to decode basic token")
	ErrOpenShiftTokenRequired = errors.New("expected openshift bearer token as password for basic token to registry")
	ErrNamespaceRequired      = errors.New("repository namespace required")
	ErrOpenShiftAccessDenied  = errors.New("openshift access denied")
)

// Error returns the internal error string for this authChallenge.
func (ac *authChallenge) Error() string {
	return ac.err.Error()
}

// Status returns the HTTP Response Status Code for this authChallenge.
func (ac *authChallenge) Status() int {
	return http.StatusUnauthorized
}

// challengeParams constructs the value to be used in
// the WWW-Authenticate response challenge header.
// See https://tools.ietf.org/html/rfc6750#section-3
func (ac *authChallenge) challengeParams() string {
	return fmt.Sprintf("Basic error=%s", ac.Error())
}

// SetHeader sets the WWW-Authenticate value for the given header.
func (ac *authChallenge) SetHeader(header http.Header) {
	header.Add("WWW-Authenticate", ac.challengeParams())
}

// ServeHttp handles writing the challenge response
// by setting the challenge header and status code.
func (ac *authChallenge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ac.SetHeader(w.Header())
	w.WriteHeader(ac.Status())
}

func VerifyOpenShiftAccess(osAccess *OpenShiftAccess, ac *AccessController) error {
	url := fmt.Sprintf("%s/subjectAccessReviews?namespace=%s", ac.OpenShiftAddr, osAccess.Namespace)
	sar := map[string]string{
		"kind":         "SubjectAccessReview",
		"apiVersion":   ac.OpenShiftApiVersion,
		"verb":         osAccess.Verb,
		"resource":     "imageRepositories",
		"resourceName": osAccess.ImageRepo,
	}

	body, err := json.Marshal(sar)
	if err != nil {
		return fmt.Errorf("Error marshaling openshift SubjectAccessReview: %s", sar)
	}
	req, err := http.NewRequest("POST", url, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("Error creating openshift request: %s", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", osAccess.BearerToken))

	resp, err := ac.Client.Do(req)
	if err != nil {
		return fmt.Errorf("Error querying openshift for SubjectAccessReview: %s", err)
	}
	defer resp.Body.Close()
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Error reading openshift SubjectAccessReview response body: %s", err)
	}

	var accessResponse authorizationapi.SubjectAccessReviewResponse
	err = json.Unmarshal(respBody, &accessResponse)
	if err != nil {
		return ErrOpenShiftAccessDenied
	}
	if !accessResponse.Allowed {
		log.Errorf("openshift access denied: %s", accessResponse.Reason)
		return ErrOpenShiftAccessDenied
	}
	return nil
}

// Authorized handles checking whether the given request is authorized
// for actions on resources allowed by openshift.
func (ac *AccessController) Authorized(ctx context.Context, accessRecords ...auth.Access) (context.Context, error) {
	req, err := ctxu.GetRequest(ctx)
	if err != nil {
		return nil, err
	}
	challenge := &authChallenge{}

	authParts := strings.Split(req.Header.Get("Authorization"), " ")
	if len(authParts) != 2 || strings.ToLower(authParts[0]) != "basic" {
		challenge.err = ErrTokenRequired
		return nil, challenge
	}
	basicToken := authParts[1]

	if len(accessRecords) == 0 {
		return ctx, nil
	}

	bearerToken := ""
	for _, access := range accessRecords {
		//fmt.Printf("%s:%s:%s", access.Resource.Type, access.Resource.Name, access.Action)

		if access.Resource.Type != "repository" {
			continue
		}

		if len(bearerToken) == 0 {
			payload, err := base64.StdEncoding.DecodeString(basicToken)
			if err != nil {
				log.Errorf("Basic token decode failed: %s", err)
				challenge.err = ErrTokenInvalid
				return nil, challenge
			}
			authParts = strings.Split(string(payload), ":")
			if len(authParts) != 2 {
				challenge.err = ErrOpenShiftTokenRequired
				return nil, challenge
			}
			bearerToken = authParts[1]
		}

		repoParts := strings.Split(access.Resource.Name, "/")
		if len(repoParts) != 2 {
			challenge.err = ErrNamespaceRequired
			return nil, challenge
		}
		osAccess := &OpenShiftAccess{
			Namespace:   repoParts[0],
			ImageRepo:   repoParts[1],
			BearerToken: bearerToken,
		}

		switch access.Action {
		case "push":
			osAccess.Verb = "create"
		case "pull":
			osAccess.Verb = "get"
		default:
			challenge.err = fmt.Errorf("Unkown action: %s", access.Action)
			return nil, challenge
		}

		err = VerifyOpenShiftAccess(osAccess, ac)
		if err != nil {
			challenge.err = err
			return nil, challenge
		}
	}
	return ctx, nil
}

func getOpenShiftTransport(options map[string]interface{}) (*http.Transport, error) {
	if _, present := options["tlsConfig"]; !present {
		log.Warn("openshift TLS config not found, using insecure client connection")
		return &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}, nil
	}

	tlsConfig := make(map[string]interface{})
	for k, v := range options["tlsConfig"].(map[interface{}]interface{}) {
		switch k := k.(type) {
		case string:
			tlsConfig[k] = v
		}
	}

	caPath, _ := tlsConfig["caPath"].(string)
	certPath, _ := tlsConfig["certPath"].(string)
	keyPath, _ := tlsConfig["keyPath"].(string)
	if len(caPath) == 0 || len(certPath) == 0 || len(keyPath) == 0 {
		return nil, fmt.Errorf("Missing TLS config params caPath/certPath/keyPath")
	}

	caData, err := ioutil.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("Error reading data from caPath: %s", caPath)
	}
	certData, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("Error reading data from certPath: %s", certPath)
	}
	keyData, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("Error reading data from keyPath: %s", keyPath)
	}

	rootPool := x509.NewCertPool()
	pemBlock, _ := pem.Decode([]byte(caData))
	if pemBlock != nil {
		caCert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("Error parsing CA certificate data: %s", err)
		}
		rootPool.AddCert(caCert)
	}

	clientCert, err := tls.X509KeyPair([]byte(certData), []byte(keyData))
	if err != nil {
		return nil, fmt.Errorf("Error parsing client certificate data: %s", err)
	}

	return &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      rootPool,
			Certificates: []tls.Certificate{clientCert},
		},
	}, nil
}

func newAccessController(options map[string]interface{}) (auth.AccessController, error) {
	fmt.Println("Using OpenShift Auth handler")

	openshiftAddr, present := options["addr"]
	if _, ok := openshiftAddr.(string); !present || !ok {
		return nil, fmt.Errorf(`"addr" must be set for openshift access controller`)
	}
	openshiftApiVersion, present := options["apiVersion"]
	if _, ok := openshiftApiVersion.(string); !present || !ok {
		return nil, fmt.Errorf(`"apiVersion" must be set for openshift access controller`)
	}

	tr, err := getOpenShiftTransport(options)
	if err != nil {
		return nil, err
	}
	return &AccessController{
		OpenShiftAddr:       openshiftAddr.(string),
		OpenShiftApiVersion: openshiftApiVersion.(string),
		Client:              &http.Client{Transport: tr},
	}, nil
}

func init() {
	auth.Register("openshift", auth.InitFunc(newAccessController))
}
