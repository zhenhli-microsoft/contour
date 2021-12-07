// Copyright Project Contour Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package envoy

import (
	"crypto/sha1" // nolint:gosec
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/projectcontour/contour/internal/dag"
	"github.com/prometheus/common/log"
)

const (
	SecretTypeCertificate       = 0
	SecretTypeValidationContext = 1
)

type SecretName struct {
	Type                  int      `json:"type"`
	CertName              string   `json:"certname"`
	San                   string   `json:"san,omitempty"`
	CRLDistributionPoints []string `json:"crlDistributionPoints,omitempty"`
}

func EncodeSecretName(s SecretName) string {
	if s.Type == SecretTypeCertificate && s.San != "" {
		log.Errorf("san is not empty when encoding secret name of certificate %+v", s.CertName)
		return fmt.Sprintf("error with certName: '%+v'", s.CertName)
	}

	bytes, err := json.Marshal(s)
	if err != nil {
		log.Errorf("Failed to encode secret name: %+v", err)
		return fmt.Sprintf("error with certName: '%+v' and san '%+v'", s.CertName, s.San)
	}
	return base64.StdEncoding.EncodeToString(bytes)
}

func DecodeSecretname(secretName string) SecretName {
	bytes, err := base64.StdEncoding.DecodeString(secretName)
	if err != nil {
		log.Errorf("Failed to decode secret name from base64: %+v", err)
	}
	var result SecretName
	err = json.Unmarshal(bytes, result)
	if err != nil {
		log.Errorf("Failed to decode secret name from json: %+v", err)
	}
	return result
}

// Secretname returns the name of the SDS secret for this secret.
func Secretname(s *dag.Secret) string {
	if s.CertName != "" {
		return EncodeSecretName(SecretName{
			Type:     SecretTypeCertificate,
			CertName: s.CertName,
		})
	}
	// This isn't a crypto hash, we just want a unique name.
	hash := sha1.Sum(s.Cert()) // nolint:gosec
	ns := s.Namespace()
	name := s.Name()
	return Hashname(60, ns, name, fmt.Sprintf("%x", hash[:5]))
}

func ValidationContextName(vc *dag.PeerValidationContext) string {
	return EncodeSecretName(SecretName{
		Type:                  SecretTypeValidationContext,
		CertName:              vc.CACertificate.CertName,
		San:                   vc.SubjectName,
		CRLDistributionPoints: vc.CRLDistributionPoints,
	})
}
