/*
Copyright 2021 Gravitational, Inc.

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

package auth

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"
	"go.mozilla.org/pkcs7"
)

func checkEC2AllowRules(iid ec2metadata.EC2InstanceIdentityDocument, token types.ProvisionToken) error {
	allowRules := token.GetAllowRules()
	for _, rule := range allowRules {
		if len(rule.AWSAccount) > 0 {
			if rule.AWSAccount != iid.AccountID {
				continue
			}
		}
		if len(rule.AWSRegions) > 0 {
			matchingRegion := false
			for _, region := range rule.AWSRegions {
				if region == iid.Region {
					matchingRegion = true
					break
				}
			}
			if !matchingRegion {
				continue
			}
		}
		// iid matches this allow rule
		return nil
	}
	return trace.AccessDenied("instance did not match any allow rules")
}

func (a *Server) CheckEC2Request(req RegisterUsingTokenRequest) error {
	if req.EC2IdentityDocument == nil {
		return nil
	}

	token, err := a.GetCache().GetToken(context.TODO(), req.Token)
	if err != nil {
		return trace.Wrap(err)
	}

	sigPEM := fmt.Sprintf("-----BEGIN PKCS7-----\n%s\n-----END PKCS7-----", string(req.EC2IdentityDocument))
	sigBER, _ := pem.Decode([]byte(sigPEM))
	if sigBER == nil {
		return trace.BadParameter("")
	}

	p7, err := pkcs7.Parse(sigBER.Bytes)
	if err != nil {
		return trace.Wrap(err)
	}

	var iid ec2metadata.EC2InstanceIdentityDocument
	if err := json.Unmarshal(p7.Content, &iid); err != nil {
		return trace.Wrap(err)
	}

	if err := checkEC2AllowRules; err != nil {
		return trace.Wrap(err)
	}

	awsCert, ok := awsCerts[iid.Region]
	if !ok {
		return trace.AccessDenied("unsupported EC2 region: %q", iid.Region)
	}

	p7.Certificates = []*x509.Certificate{awsCert}
	if err = p7.Verify(); err != nil {
		return trace.AccessDenied("invalid signature")
	}

	return nil
}

var awsCertBytes = map[string][]byte{
	"us-west-2": []byte(`-----BEGIN CERTIFICATE-----
MIIEEjCCAvqgAwIBAgIJALZL3lrQCSTMMA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNV
BAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0
dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAgFw0xNTA4MTQw
OTAxMzJaGA8yMTk1MDExNzA5MDEzMlowXDELMAkGA1UEBhMCVVMxGTAXBgNVBAgT
EFdhc2hpbmd0b24gU3RhdGUxEDAOBgNVBAcTB1NlYXR0bGUxIDAeBgNVBAoTF0Ft
YXpvbiBXZWIgU2VydmljZXMgTExDMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA02Y59qtAA0a6uzo7nEQcnJ26OKF+LRPwZfixBH+EbEN/Fx0gYy1jpjCP
s5+VRNg6/WbfqAsV6X2VSjUKN59ZMnMY9ALA/Ipz0n00Huxj38EBZmX/NdNqKm7C
qWu1q5kmIvYjKGiadfboU8wLwLcHo8ywvfgI6FiGGsEO9VMC56E/hL6Cohko11LW
dizyvRcvg/IidazVkJQCN/4zC9PUOVyKdhW33jXy8BTg/QH927QuNk+ZzD7HH//y
tIYxDhR6TIZsSnRjz3bOcEHxt1nsidc65mY0ejQty4hy7ioSiapw316mdbtE+RTN
fcH9FPIFKQNBpiqfAW5Ebp3Lal3/+wIDAQABo4HUMIHRMAsGA1UdDwQEAwIHgDAd
BgNVHQ4EFgQU7coQx8Qnd75qA9XotSWT3IhvJmowgY4GA1UdIwSBhjCBg4AU7coQ
x8Qnd75qA9XotSWT3IhvJmqhYKReMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBX
YXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6
b24gV2ViIFNlcnZpY2VzIExMQ4IJALZL3lrQCSTMMBIGA1UdEwEB/wQIMAYBAf8C
AQAwDQYJKoZIhvcNAQELBQADggEBAFZ1e2MnzRaXCaLwEC1pW/f0oRG8nHrlPZ9W
OYZEWbh+QanRgaikBNDtVTwARQcZm3z+HWSkaIx3cyb6vM0DSkZuiwzm1LJ9rDPc
aBm03SEt5v8mcc7sXWvgFjCnUpzosmky6JheCD4O1Cf8k0olZ93FQnTrbg62OK0h
83mGCDeVKU3hLH97FYoUq+3N/IliWFDhvibAYYKFJydZLhIdlCiiB99AM6Sg53rm
oukS3csyUxZyTU2hQfdjyo1nqW9yhvFAKjnnggiwxNKTTPZzstKW8+cnYwiiTwJN
QpVoZdt0SfbuNnmwRUMi+QbuccXweav29QeQ3ADqjgB0CZdSRKk=
-----END CERTIFICATE-----`),
}

var awsCerts map[string]*x509.Certificate

func init() {
	for region, certBytes := range awsCertBytes {
		certPEM, _ := pem.Decode(certBytes)
		cert, err := x509.ParseCertificate(certPEM.Bytes)
		if err != nil {
			panic(err)
		}
		awsCerts[region] = cert
	}
}
