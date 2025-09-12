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

package controller

import (
	"context"
	"fmt"
	"reflect"

	"github.com/ansg191/oauth-proxy-op/internal/images"
	"github.com/stoewer/go-strcase"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	oauthv1 "github.com/ansg191/oauth-proxy-op/api/v1"
)

// ProxyReconciler reconciles a Proxy object
type ProxyReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Registry images.Registry
}

// +kubebuilder:rbac:groups=oauth.anshulg.com,resources=proxies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=oauth.anshulg.com,resources=proxies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=oauth.anshulg.com,resources=proxies/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=deployment,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Proxy object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile
func (r *ProxyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var proxy oauthv1.Proxy
	if err := r.Get(ctx, req.NamespacedName, &proxy); err != nil {
		log.Error(err, "unable to fetch Proxy")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	svc := &v1.Service{ObjectMeta: metav1.ObjectMeta{Name: r.resName(&proxy), Namespace: proxy.Namespace}}
	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, svc, func() error {
		newSvc, err := r.createSvc(&proxy)
		if err != nil {
			return err
		}
		svc.ObjectMeta = newSvc.ObjectMeta
		svc.Spec = newSvc.Spec
		return nil
	})
	if err != nil {
		return ctrl.Result{}, err
	}
	log.Info("Reconciled Service", "op", op)

	secret := &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: r.resName(&proxy), Namespace: proxy.Namespace}}
	op, err = controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		newSecret, err := r.createSecret(&proxy)
		if err != nil {
			return err
		}
		secret.ObjectMeta = newSecret.ObjectMeta
		secret.Type = newSecret.Type
		secret.Data = newSecret.Data
		return nil
	})
	if err != nil {
		return ctrl.Result{}, err
	}
	log.Info("Reconciled Secret", "op", op)

	deploy := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: r.resName(&proxy), Namespace: proxy.Namespace}}
	op, err = controllerutil.CreateOrUpdate(ctx, r.Client, deploy, func() error {
		newDeploy, err := r.createDeployment(ctx, &proxy)
		if err != nil {
			return err
		}
		deploy.ObjectMeta = newDeploy.ObjectMeta
		deploy.Spec = newDeploy.Spec
		return nil
	})
	if err != nil {
		return ctrl.Result{}, err
	}
	log.Info("Reconciled Deployment", "op", op)

	return ctrl.Result{}, nil
}

func (r *ProxyReconciler) resName(proxy *oauthv1.Proxy) string {
	return fmt.Sprintf("oauth-%s", proxy.Name)
}

func (r *ProxyReconciler) resLabels(proxy *oauthv1.Proxy) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name": r.resName(proxy),
	}
}

func (r *ProxyReconciler) createSvc(proxy *oauthv1.Proxy) (*v1.Service, error) {
	name := r.resName(proxy)

	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Labels:      r.resLabels(proxy),
			Annotations: make(map[string]string),
			Name:        name,
			Namespace:   proxy.Namespace,
		},
		Spec: proxy.Spec.Service,
	}

	// Override service properties
	if svc.Spec.Selector == nil {
		svc.Spec.Selector = r.resLabels(proxy)
	}
	if svc.Spec.Type == "" {
		svc.Spec.Type = v1.ServiceTypeClusterIP
	}
	if len(svc.Spec.Ports) == 0 {
		svc.Spec.Ports = []v1.ServicePort{
			{
				Name:       "http",
				Port:       80,
				TargetPort: intstr.FromInt32(4180),
			},
		}
		if proxy.Spec.Tls != nil {
			svc.Spec.Ports = append(svc.Spec.Ports, v1.ServicePort{
				Name:       "https",
				Port:       443,
				TargetPort: intstr.FromInt32(4443),
			})
		}
	}

	if err := ctrl.SetControllerReference(proxy, svc, r.Scheme); err != nil {
		return nil, err
	}

	return svc, nil
}

func (r *ProxyReconciler) createSecret(proxy *oauthv1.Proxy) (*v1.Secret, error) {
	name := r.resName(proxy)

	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   proxy.Namespace,
			Labels:      r.resLabels(proxy),
			Annotations: make(map[string]string),
		},
		Type: v1.SecretTypeOpaque,
		Data: make(map[string][]byte),
	}

	// Populate standard secret data
	addEnvVar(secret.Data, "http_address", "0.0.0.0:4180")

	// Populate secret data based on proxy spec
	addEnvVar(secret.Data, "provider", proxy.Spec.Provider.Type)
	addEnvVar(secret.Data, "client_id", proxy.Spec.Provider.ClientId)
	addEnvVar(secret.Data, "client_secret", proxy.Spec.Provider.ClientSecret)
	addEnvVar(secret.Data, "code_challenge_method", proxy.Spec.Provider.CodeChallengeMethod)
	addEnvVar(secret.Data, "oidc_issuer_url", proxy.Spec.Provider.OidcIssuerUrl)
	addEnvVar(secret.Data, "cookie_httponly", proxy.Spec.Cookie.HttpOnly)
	addEnvVar(secret.Data, "cookie_name", proxy.Spec.Cookie.Name)
	addEnvVar(secret.Data, "cookie_samesite", proxy.Spec.Cookie.SameSite)
	addEnvVar(secret.Data, "cookie_secret", proxy.Spec.Cookie.Secret)
	addEnvVar(secret.Data, "cookie_secure", proxy.Spec.Cookie.Secure)
	addEnvVar(secret.Data, "email_domains", proxy.Spec.Proxy.EmailDomains)
	addEnvVar(secret.Data, "reverse_proxy", proxy.Spec.Proxy.ReverseProxy)
	addEnvVar(secret.Data, "upstreams", proxy.Spec.Upstream.Upstreams)

	if proxy.Spec.Tls != nil {
		addEnvVar(secret.Data, "https_address", "0.0.0.0:4443")
		addEnvVar(secret.Data, "tls_cert_file", "/certs/tls.crt")
		addEnvVar(secret.Data, "tls_key_file", "/certs/tls.key")

		addEnvVar(secret.Data, "tls_min_version", proxy.Spec.Tls.MinVersion)
	}

	if err := ctrl.SetControllerReference(proxy, secret, r.Scheme); err != nil {
		return nil, err
	}
	return secret, nil
}

func addEnvVar(data map[string][]byte, name string, value any) {
	val := encodeEnvVar(value)
	if val == nil {
		return
	}
	key := fmt.Sprintf("OAUTH2_PROXY_%s", strcase.UpperSnakeCase(name))
	data[key] = val
}

func encodeEnvVar(value any) []byte {
	rv := reflect.ValueOf(value)
	for rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}

	var val []byte
	switch rv.Kind() {
	case reflect.Bool:
		val = []byte(fmt.Sprintf("%t", rv.Bool()))
	case reflect.String:
		val = []byte(rv.String())
	case reflect.Slice:
		// Join slice elements with comma
		for i := 0; i < rv.Len(); i++ {
			encoded := encodeEnvVar(rv.Index(i).Interface())
			if encoded == nil {
				continue
			}
			if val != nil {
				val = append(val, ',')
			}
			val = append(val, encoded...)
		}
	default:
		panic(fmt.Sprintf("unsupported type %s", rv.Kind()))
	}
	return val
}

func (r *ProxyReconciler) createDeployment(ctx context.Context, proxy *oauthv1.Proxy) (*appsv1.Deployment, error) {
	name := r.resName(proxy)

	var envVars []v1.EnvVar
	if proxy.Spec.Provider.ClientExistingSecret != nil {
		envVars = append(envVars, v1.EnvVar{
			Name: "OAUTH2_PROXY_CLIENT_SECRET",
			ValueFrom: &v1.EnvVarSource{
				SecretKeyRef: proxy.Spec.Provider.ClientExistingSecret,
			},
		})
	}
	if proxy.Spec.Cookie.ExistingSecret != nil {
		envVars = append(envVars, v1.EnvVar{
			Name: "OAUTH2_PROXY_COOKIE_SECRET",
			ValueFrom: &v1.EnvVarSource{
				SecretKeyRef: proxy.Spec.Cookie.ExistingSecret,
			},
		})
	}

	img, err := r.Registry.LatestImage(ctx, images.DefaultRepo)
	if err != nil {
		return nil, err
	}

	ports := []v1.ContainerPort{{
		Name:          "http",
		ContainerPort: 4180,
		Protocol:      v1.ProtocolTCP,
	}}
	if proxy.Spec.Tls != nil {
		ports = append(ports, v1.ContainerPort{
			Name:          "https",
			ContainerPort: 4443,
			Protocol:      v1.ProtocolTCP,
		})
	}

	checkPort := int32(4180)
	if proxy.Spec.Tls != nil {
		checkPort = 4443
	}
	checkScheme := v1.URISchemeHTTP
	if proxy.Spec.Tls != nil {
		checkScheme = v1.URISchemeHTTPS
	}

	var volumes []v1.Volume
	if proxy.Spec.Tls != nil {
		volumes = append(volumes, v1.Volume{
			Name:         "certs",
			VolumeSource: proxy.Spec.Tls.Volume,
		})
	}

	var mounts []v1.VolumeMount
	if proxy.Spec.Tls != nil {
		mounts = append(mounts, v1.VolumeMount{
			Name:      "certs",
			ReadOnly:  true,
			MountPath: "/certs",
		})
	}

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Labels:      r.resLabels(proxy),
			Annotations: make(map[string]string),
			Name:        name,
			Namespace:   proxy.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](1),
			Selector: &metav1.LabelSelector{
				MatchLabels: r.resLabels(proxy),
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:   name,
					Labels: r.resLabels(proxy),
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{{
						Name:  "oauth-proxy",
						Image: img.String(),
						Ports: ports,
						EnvFrom: []v1.EnvFromSource{{
							SecretRef: &v1.SecretEnvSource{
								LocalObjectReference: v1.LocalObjectReference{
									Name: name,
								},
							},
						}},
						Env: envVars,
						Resources: v1.ResourceRequirements{
							Requests: v1.ResourceList{
								v1.ResourceCPU:    resource.MustParse("25m"),
								v1.ResourceMemory: resource.MustParse("32Mi"),
							},
							Limits: v1.ResourceList{
								v1.ResourceMemory: resource.MustParse("128Mi"),
							},
						},
						VolumeMounts: mounts,
						LivenessProbe: &v1.Probe{
							ProbeHandler: v1.ProbeHandler{
								HTTPGet: &v1.HTTPGetAction{
									Path:   "/ping",
									Port:   intstr.FromInt32(checkPort),
									Scheme: checkScheme,
								},
							},
						},
						ReadinessProbe: &v1.Probe{
							ProbeHandler: v1.ProbeHandler{
								HTTPGet: &v1.HTTPGetAction{
									Path:   "/ready",
									Port:   intstr.FromInt32(checkPort),
									Scheme: checkScheme,
								},
							},
						},
						ImagePullPolicy: v1.PullIfNotPresent,
						SecurityContext: &v1.SecurityContext{
							RunAsUser:                ptr.To[int64](2000),
							RunAsGroup:               ptr.To[int64](2000),
							RunAsNonRoot:             ptr.To(true),
							Privileged:               ptr.To(false),
							AllowPrivilegeEscalation: ptr.To(false),
							Capabilities:             &v1.Capabilities{Drop: []v1.Capability{"ALL"}},
							ReadOnlyRootFilesystem:   ptr.To(true),
							SeccompProfile: &v1.SeccompProfile{
								Type: v1.SeccompProfileTypeRuntimeDefault,
							},
						},
					}},
					RestartPolicy: v1.RestartPolicyAlways,
					SecurityContext: &v1.PodSecurityContext{
						FSGroup: ptr.To[int64](2000),
					},
					Volumes: volumes,
				},
			},
		},
	}

	if err := ctrl.SetControllerReference(proxy, deployment, r.Scheme); err != nil {
		return nil, err
	}

	return deployment, nil
}

var (
	svcOwnerKey = ".metadata.controller"
	apiGVStr    = oauthv1.GroupVersion.String()
)

// SetupWithManager sets up the controller with the Manager.
func (r *ProxyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &v1.Service{}, svcOwnerKey, func(rawObj client.Object) []string {
		svc := rawObj.(*v1.Service)
		owner := metav1.GetControllerOf(svc)
		if owner == nil {
			return nil
		}
		if owner.APIVersion != apiGVStr || owner.Kind != "Proxy" {
			return nil
		}

		return []string{owner.Name}
	}); err != nil {
		return err
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &v1.Secret{}, svcOwnerKey, func(rawObj client.Object) []string {
		secret := rawObj.(*v1.Secret)
		owner := metav1.GetControllerOf(secret)
		if owner == nil {
			return nil
		}
		if owner.APIVersion != apiGVStr || owner.Kind != "Proxy" {
			return nil
		}

		return []string{owner.Name}
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&oauthv1.Proxy{}).
		Owns(&v1.Service{}).
		Owns(&v1.Secret{}).
		Named("proxy").
		Complete(r)
}
