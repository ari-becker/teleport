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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/davecgh/go-spew/spew"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"
	"go.mozilla.org/pkcs7"
)

func checkEC2AllowRules(iid *imds.InstanceIdentityDocument, token types.ProvisionToken) error {
	allowRules := token.GetAllowRules()
	for _, rule := range allowRules {
		spew.Dump(rule)
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
		// iid matches this allow rule. Check if it is running.
		return trace.Wrap(checkInstanceRunning(iid.InstanceID, rule.AWSRole))
	}
	return trace.AccessDenied("instance did not match any allow rules")
}

func checkInstanceRunning(instanceID, role string) error {
	println("NIC checkInstanceRunning")
	config, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return trace.Wrap(err)
	}

	// assume the role if necessary
	if role != "" {
		stsClient := sts.NewFromConfig(config)
		creds := stscreds.NewAssumeRoleProvider(stsClient, role)
		config.Credentials = aws.NewCredentialsCache(creds)
	}

	ec2Client := ec2.NewFromConfig(config)

	output, err := ec2Client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return trace.Wrap(err)
	}

	if len(output.Reservations) == 0 || len(output.Reservations[0].Instances) == 0 {
		return trace.AccessDenied("")
	}
	instance := output.Reservations[0].Instances[0]
	if instance.InstanceId == nil || *instance.InstanceId != instanceID {
		return trace.AccessDenied("")
	}
	if instance.State == nil || instance.State.Code == nil || instance.State.Name != ec2types.InstanceStateNameRunning {
		return trace.AccessDenied("")
	}
	return nil
}

func parseAndCheckIID(iidBytes []byte) (*imds.InstanceIdentityDocument, error) {
	sigPEM := fmt.Sprintf("-----BEGIN PKCS7-----\n%s\n-----END PKCS7-----", string(iidBytes))
	sigBER, _ := pem.Decode([]byte(sigPEM))
	if sigBER == nil {
		return nil, trace.AccessDenied("unable to decode Instance Identity Document")
	}

	p7, err := pkcs7.Parse(sigBER.Bytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var iid imds.InstanceIdentityDocument
	if err := json.Unmarshal(p7.Content, &iid); err != nil {
		return nil, trace.Wrap(err)
	}
	spew.Dump(iid)

	awsCert, ok := awsCerts[iid.Region]
	if !ok {
		return nil, trace.AccessDenied("unsupported EC2 region: %q", iid.Region)
	}
	p7.Certificates = []*x509.Certificate{awsCert}
	if err = p7.Verify(); err != nil {
		return nil, trace.AccessDenied("invalid signature")
	}
	return &iid, nil
}

func (a *Server) checkInstanceUnique(req RegisterUsingTokenRequest, iid *imds.InstanceIdentityDocument) error {
	// make sure this instance has not already joined the cluster
	if req.NodeName != iid.AccountID+"-"+iid.InstanceID {
		return trace.AccessDenied("invalid host name %q, expected %q", req.NodeName, iid.AccountID+"-"+iid.InstanceID)
	}
	namespaces, err := a.GetNamespaces()
	if err != nil {
		return trace.Wrap(err)
	}
	for _, namespace := range namespaces {
		_, err := a.GetNode(context.TODO(), namespace.GetName(), req.NodeName)
		if trace.IsNotFound(err) {
			continue
		} else if err != nil {
			return trace.Wrap(err)
		} else {
			return trace.AccessDenied("node with this name already exists")
		}
	}
	return nil
}

func (a *Server) CheckEC2Request(req RegisterUsingTokenRequest) error {
	println("NIC CheckEC2Request")
	if req.EC2IdentityDocument == nil {
		// not a simplified node joining request
		return nil
	}

	token, err := a.GetCache().GetToken(context.TODO(), req.Token)
	if err != nil {
		return trace.Wrap(err)
	}

	iid, err := parseAndCheckIID(req.EC2IdentityDocument)
	if err != nil {
		return trace.Wrap(err)
	}

	if err := a.checkInstanceUnique(req, iid); err != nil {
		return trace.Wrap(err)
	}

	if err := checkEC2AllowRules(iid, token); err != nil {
		return trace.Wrap(err)
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

var awsCerts = map[string]*x509.Certificate{}

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
