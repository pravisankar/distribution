package openshift

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/docker/distribution/registry/auth"
	"golang.org/x/net/context"
)

func httpTestTools(code int, body string) (*httptest.Server, *http.Client) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, body)
	}))

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy: func(req *http.Request) (*url.URL, error) {
			return url.Parse(server.URL)
		},
	}

	client := &http.Client{Transport: transport}
	return server, client
}

// TestVerifyOpenShiftAccess mocks openshift http request/response and
// tests invalid/valid/scoped openshift tokens.
func TestVerifyOpenShiftAccess(t *testing.T) {
	// Test invalid openshift bearer token
	server, client := httpTestTools(401, "Unauthorized")
	defer server.Close()
	ac := &AccessController{server.URL, "v1beta1", client}
	osAccess := &OpenShiftAccess{"foo", "bar", "create", "magic bearer token"}
	err := VerifyOpenShiftAccess(osAccess, ac)
	if err.Error() != ErrOpenShiftAccessDenied.Error() {
		t.Fatal("VerifyOpenShiftAccess did not get expected error - got %s - expected %s", err, ErrOpenShiftTokenRequired)
	}

	// Test valid openshift bearer token but token *not* scoped for create operation
	server, client = httpTestTools(200, `{"namespace": "foo", "allowed": false, "reason": "not authorized!", "kind": "SubjectAccessReviewResponse", "apiVersion": "v1beta1"}`)
	defer server.Close()
	ac = &AccessController{server.URL, "v1beta1", client}
	osAccess = &OpenShiftAccess{"foo", "bar", "create", "magic bearer token"}
	err = VerifyOpenShiftAccess(osAccess, ac)
	if err.Error() != ErrOpenShiftAccessDenied.Error() {
		t.Fatal("VerifyOpenShiftAccess did not get expected error - got %s - expected %s", err, ErrOpenShiftTokenRequired)
	}

	// Test valid openshift bearer token and token scoped for create operation
	server, client = httpTestTools(200, `{"namespace": "foo", "allowed": true, "reason": "authorized!", "kind": "SubjectAccessReviewResponse", "apiVersion": "v1beta1"}`)
	defer server.Close()
	ac = &AccessController{server.URL, "v1beta1", client}
	osAccess = &OpenShiftAccess{"foo", "bar", "create", "magic bearer token"}
	err = VerifyOpenShiftAccess(osAccess, ac)
	if err != nil {
		t.Fatalf("expected nil for VerifyOpenShiftAccess but got %s", err)
	}
}

// TestAccessController tests complete integration of the auth package.
func TestAccessController(t *testing.T) {
	options := map[string]interface{}{
		"addr":       "https://openshift.example.com/osapi",
		"apiVersion": "v1beta1",
	}

	accessController, err := newAccessController(options)
	if err != nil {
		t.Fatal(err)
	}

	// Test request with no token.
	req, err := http.NewRequest("GET", options["addr"].(string), nil)
	if err != nil {
		t.Fatal(err)
	}
	testAccess := auth.Access{}
	ctx := context.WithValue(nil, "http.request", req)
	authCtx, err := accessController.Authorized(ctx, testAccess)
	challenge, ok := err.(auth.Challenge)
	if !ok {
		t.Fatal("accessController did not return a challenge")
	}
	if challenge.Error() != ErrTokenRequired.Error() {
		t.Fatalf("accessController did not get expected error - got %s - expected %s", challenge, ErrTokenRequired)
	}
	if authCtx != nil {
		t.Fatalf("expected nil auth context but got %s", authCtx)
	}

	// Test request with registry token but does not involve any repository operation.
	req.Header.Set("Authorization", fmt.Sprintf("Basic abcdefgh"))
	authCtx, err = accessController.Authorized(ctx, testAccess)
	if err != nil {
		t.Fatal(err)
	}
	if authCtx == nil {
		t.Fatal("expected auth context but got nil")
	}

	// Test request with invalid registry token.
	req.Header.Set("Authorization", fmt.Sprintf("Basic ab-cd-ef-gh"))
	testAccess = auth.Access{
		Resource: auth.Resource{Type: "repository"},
	}
	authCtx, err = accessController.Authorized(ctx, testAccess)
	challenge, ok = err.(auth.Challenge)
	if !ok {
		t.Fatal("accessController did not return a challenge")
	}
	if challenge.Error() != ErrTokenInvalid.Error() {
		t.Fatalf("accessController did not get expected error - got %s - expected %s", challenge, ErrTokenInvalid)
	}
	if authCtx != nil {
		t.Fatalf("expected nil auth context but got %s", authCtx)
	}

	// Test request with invalid openshift bearer token.
	req.Header.Set("Authorization", fmt.Sprintf("Basic abcdefgh"))
	authCtx, err = accessController.Authorized(ctx, testAccess)
	challenge, ok = err.(auth.Challenge)
	if !ok {
		t.Fatal("accessController did not return a challenge")
	}
	if challenge.Error() != ErrOpenShiftTokenRequired.Error() {
		t.Fatalf("accessController did not get expected error - got %s - expected %s", challenge, ErrOpenShiftTokenRequired)
	}
	if authCtx != nil {
		t.Fatalf("expected nil auth context but got %s", authCtx)
	}

	// Test request with valid openshift token but invalid namespace.
	req.Header.Set("Authorization", fmt.Sprintf("Basic b3BlbnNoaWZ0OmF3ZXNvbWU="))
	testAccess = auth.Access{
		Resource: auth.Resource{
			Type: "repository",
			Name: "bar",
		},
		Action: "pull",
	}
	authCtx, err = accessController.Authorized(ctx, testAccess)
	challenge, ok = err.(auth.Challenge)
	if !ok {
		t.Fatal("accessController did not return a challenge")
	}
	if challenge.Error() != ErrNamespaceRequired.Error() {
		t.Fatalf("accessController did not get expected error - got %s - expected %s", challenge, ErrNamespaceRequired)
	}
	if authCtx != nil {
		t.Fatalf("expected nil auth context but got %s", authCtx)
	}

	// Test request with valid openshift token but token not scoped for the given repo operation.
	req.Header.Set("Authorization", fmt.Sprintf("Basic b3BlbnNoaWZ0OmF3ZXNvbWU="))
	testAccess = auth.Access{
		Resource: auth.Resource{
			Type: "repository",
			Name: "foo/bar",
		},
		Action: "pull",
	}
	authCtx, err = accessController.Authorized(ctx, testAccess)
	if err == nil {
		t.Fatalf("accessController did not get any error")
	}
	if authCtx != nil {
		t.Fatalf("expected nil auth context but got %s", authCtx)
	}
}
