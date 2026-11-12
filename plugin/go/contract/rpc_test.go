package contract

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecureRPCHandlerRequiresExactBearerToken(t *testing.T) {
	plugin := &Plugin{config: Config{RPCAuthToken: "secret-token", RPCMaxConcurrent: 2}}
	handler := plugin.secureRPCHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	tests := []struct {
		name          string
		authorization string
		want          int
	}{
		{name: "missing", want: http.StatusUnauthorized},
		{name: "raw token", authorization: "secret-token", want: http.StatusUnauthorized},
		{name: "wrong scheme", authorization: "Basic secret-token", want: http.StatusUnauthorized},
		{name: "wrong token", authorization: "Bearer wrong", want: http.StatusUnauthorized},
		{name: "valid", authorization: "Bearer secret-token", want: http.StatusNoContent},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://plugin/health", nil)
			request.Header.Set("Authorization", test.authorization)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
		})
	}
}

func TestSubscribeBlocksEnforcesLimitAndCleansUp(t *testing.T) {
	plugin := &Plugin{
		config:           Config{RPCMaxSubscribers: 2},
		eventSubscribers: map[chan struct{}]struct{}{},
	}
	_, unsubscribeOne, ok := plugin.subscribeBlocks()
	if !ok {
		t.Fatal("first subscriber was rejected")
	}
	_, unsubscribeTwo, ok := plugin.subscribeBlocks()
	if !ok {
		t.Fatal("second subscriber was rejected")
	}
	if _, _, ok = plugin.subscribeBlocks(); ok {
		t.Fatal("subscriber above the configured maximum was accepted")
	}
	unsubscribeOne()
	_, unsubscribeThree, ok := plugin.subscribeBlocks()
	if !ok {
		t.Fatal("subscriber slot was not released")
	}
	unsubscribeTwo()
	unsubscribeThree()
	if len(plugin.eventSubscribers) != 0 {
		t.Fatalf("subscriber map contains %d leaked entries", len(plugin.eventSubscribers))
	}
}

func TestFixedWindowLimiterBoundsIdentitiesAndRequests(t *testing.T) {
	limiter := newFixedWindowLimiter(2)
	if !limiter.allow("first") || !limiter.allow("first") {
		t.Fatal("requests within the limit were rejected")
	}
	if limiter.allow("first") {
		t.Fatal("request above the limit was accepted")
	}
	limiter.maximum = 1
	if limiter.allow("second") {
		t.Fatal("identity above the bounded map size was accepted")
	}
}

func TestLoopbackListenAddress(t *testing.T) {
	for _, address := range []string{"127.0.0.1:50010", "[::1]:50010", "localhost:50010"} {
		if !loopbackListenAddress(address) {
			t.Fatalf("%s should be recognized as loopback", address)
		}
	}
	for _, address := range []string{"0.0.0.0:50010", ":50010", "192.0.2.1:50010", "invalid"} {
		if loopbackListenAddress(address) {
			t.Fatalf("%s should not be recognized as loopback", address)
		}
	}
}
