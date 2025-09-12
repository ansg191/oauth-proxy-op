/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ProxySpec defines the desired state of Proxy
type ProxySpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	// The following markers will use OpenAPI v3 schema to validate the value
	// More info: https://book.kubebuilder.io/reference/markers/crd-validation.html

	// Provider defines the authentication provider.
	// +required
	Provider ProviderConfig `json:"provider"`
	// +optional
	Cookie CookieConfig `json:"cookie"`
	// +optional
	Proxy ProxyConfig `json:"proxy"`
	// +required
	Upstream UpstreamConfig `json:"upstream"`
	// +optional
	Service v1.ServiceSpec `json:"service,omitempty"`
	// +optional
	Tls *TlsConfig `json:"tls,omitempty"`
}

type ProviderConfig struct {
	// OAuth provider.
	// +required
	// +kubebuilder:validation:Enum=oidc;
	Type string `json:"type"`
	// The OAuth Client ID, e.g. "123456.apps.googleusercontent.com".
	// +required
	ClientId string `json:"clientId"`
	// The OAuth Client Secret.
	// +optional
	ClientSecret *string `json:"clientSecret,omitempty"`
	// The OAuth Client Secret from an existing secret. Overrides clientSecret.
	// +optional
	ClientExistingSecret *v1.SecretKeySelector `json:"clientExistingSecret,omitempty"`
	// Use PKCE code challenges with the specified method. Either 'plain' or 'S256' (recommended).
	// +optional
	// +kubebuilder:validation:Enum=plain;S256
	CodeChallengeMethod *string `json:"codeChallengeMethod,omitempty"`
	// The OpenID Connect issuer URL, e.g. "https://accounts.google.com".
	// +optional
	OidcIssuerUrl *string `json:"oidcIssuerUrl,omitempty"`
}

type CookieConfig struct {
	// Set HttpOnly cookie flag.
	// +optional
	HttpOnly *bool `json:"httpOnly,omitempty"`
	// The Name of the cookie that the oauth_proxy creates.
	// Should be changed to use a cookie prefix (__Host- or __Secure-) if Secure is set.
	// +optional
	Name *string `json:"name,omitempty"`
	// Set SameSite cookie attribute ("lax", "strict", "none", or "").
	// +optional
	// +kubebuilder:validation:Enum=strict;lax;none
	SameSite *string `json:"sameSite,omitempty"`
	// The seed string for secure cookies (optionally base64 encoded)
	// +optional
	Secret *string `json:"secret,omitempty"`
	// The seed string for secure cookies (optionally base64 encoded) from an existing secret. Overrides secret.
	// +optional
	ExistingSecret *v1.SecretKeySelector `json:"existingSecret,omitempty"`
	// Set Secure (HTTPS only) cookie flag
	// +optional
	Secure *bool `json:"secure,omitempty"`
}

type ProxyConfig struct {
	// Authenticate emails with the specified domain (may be given multiple times).
	// Use * to authenticate any email.
	// +optional
	EmailDomains []string `json:"emailDomains,omitempty"`
	// Are we running behind a reverse proxy, controls whether headers like X-Real-IP are accepted and allows
	// X-Forwarded-{Proto,Host,Uri} headers to be used on redirect selection
	// +optional
	ReverseProxy *bool `json:"reverseProxy,omitempty"`
}

type UpstreamConfig struct {
	// The http url(s) of the upstream endpoint,
	// file:// paths for static files or static://<status_code> for static response.
	// Routing is based on the path
	//
	// See: https://oauth2-proxy.github.io/oauth2-proxy/configuration/overview#upstreams-configuration
	//
	// +required
	Upstreams []string `json:"upstreams"`
}

type TlsConfig struct {
	// Minimum TLS version that is acceptable, either "TLS1.2" or "TLS1.3"
	// +optional
	// +kubebuilder:validation:Enum=TLS1.2;TLS1.3
	MinVersion *string `json:"minVersion,omitempty"`
	// The TLS certificate and key.
	// Should be in PEM format with files tls.crt and tls.key.
	// +required
	Volume v1.VolumeSource `json:"volume"`
}

// ProxyStatus defines the observed state of Proxy.
type ProxyStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	// conditions represent the current state of the Proxy resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// Standard condition types include:
	// - "Available": the resource is fully functional
	// - "Progressing": the resource is being created or updated
	// - "Degraded": the resource failed to reach or maintain its desired state
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Proxy is the Schema for the proxies API
type Proxy struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of Proxy
	// +required
	Spec ProxySpec `json:"spec"`

	// status defines the observed state of Proxy
	// +optional
	Status ProxyStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// ProxyList contains a list of Proxy
type ProxyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Proxy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Proxy{}, &ProxyList{})
}
