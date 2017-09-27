/*
Copyright 2015 Home Office All rights reserved.

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

package main

import (
	"io/ioutil"
	"os"

	"github.com/hashicorp/vault/api"
)

// the userpass authentication plugin
type authKubernetesPlugin struct {
	client *api.Client
}

type kubernetesLogin struct {
	Role string `json:"role,omitempty"`
	Jwt  string `json:"jwt,omitempty"`
}

// NewkubernetesPlugin creates a new kubernetes auth plugin
func NewKubernetesPlugin(client *api.Client) AuthInterface {
	return &authKubernetesPlugin{
		client: client,
	}
}

// Create a kubernetes plugin
func (r authKubernetesPlugin) Create(cfg *vaultAuthOptions) (string, error) {
	// Handle ENV login details.. if someone needs it?
	if cfg.Username == "" {
		cfg.Username = os.Getenv("VAULT_SIDEKICK_KUBE_ROLE")
	}
	if cfg.FileName == "" {
		cfg.FileName = os.Getenv("VAULT_SIDEKICK_KUBE_JWT_FILE")
		if cfg.FileName == "" {
			cfg.FileName = "/var/run/secrets/kubernetes.io/serviceaccount/token"
		}
	}

	// Read JWT file contents
	jwt, err := ioutil.ReadFile(cfg.FileName)
	if err != nil {
		return "", err
	}
	// step: create the token request
	request := r.client.NewRequest("POST", "/v1/auth/kubernetes/login")
	login := kubernetesLogin{Jwt: string(jwt), Role: cfg.Username}
	if err := request.SetJSONBody(login); err != nil {
		return "", err
	}
	// step: make the request
	resp, err := r.client.RawRequest(request)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// step: parse and return auth
	secret, err := api.ParseSecret(resp.Body)
	if err != nil {
		return "", err
	}

	return secret.Auth.ClientToken, nil
}
