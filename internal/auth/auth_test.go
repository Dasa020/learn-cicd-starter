package auth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAPI(t *testing.T) {
	// Success: valid auth header
	originalKey := "123456789"
	headers := createAuthHeaders([]string{"ApiKey " + originalKey})
	apiKey, err := GetAPIKey(headers)
	require.NoError(t, err)
	require.NotEmpty(t, apiKey)
	assert.Equal(t, apiKey, originalKey)

	// Fail: incomplete auth header
	headers = createAuthHeaders([]string{"ApiKey"})
	apiKey, err = GetAPIKey(headers)
	require.Error(t, err)
	require.Empty(t, apiKey)

	// Fail: different auth header
	originalKey = "123456789"
	headers = createAuthHeaders([]string{"Bearer " + originalKey})
	apiKey, err = GetAPIKey(headers)
	require.Error(t, err)
	require.Empty(t, apiKey)

	// Fail: different API key returned
	originalKey = "123456789"
	headers = createAuthHeaders([]string{"ApiKey 0" + originalKey})
	apiKey, err = GetAPIKey(headers)
	require.NoError(t, err)
	require.NotEmpty(t, apiKey)
	assert.NotEqual(t, apiKey, originalKey)
}

func createAuthHeaders(vals []string) (headers http.Header) {
	headers = make(http.Header)
	headers["Authorization"] = vals

	return headers
}
