/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/chenjz24/net/http"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/client/credential"
	"github.com/hyperledger/fabric-ca/lib/client/credential/idemix"
	"github.com/hyperledger/fabric-ca/lib/client/credential/x509"
	"github.com/hyperledger/fabric-ca/lib/common"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
)

// Identity is fabric-ca's implementation of an identity
type Identity struct {
	name   string
	client *Client
	creds  []credential.Credential
}

// NewIdentity is the constructor for identity
func NewIdentity(client *Client, name string, creds []credential.Credential) *Identity {
	id := new(Identity)
	id.name = name
	id.client = client
	id.creds = creds
	return id
}

// GetName returns the identity name
func (i *Identity) GetName() string {
	return i.name
}

// GetClient returns the client associated with this identity
func (i *Identity) GetClient() *Client {
	return i.client
}

// GetIdemixCredential returns Idemix credential of this identity
func (i *Identity) GetIdemixCredential() credential.Credential {
	for _, cred := range i.creds {
		if cred.Type() == idemix.CredType {
			return cred
		}
	}
	return nil
}

// GetX509Credential returns X509 credential of this identity
func (i *Identity) GetX509Credential() credential.Credential {
	for _, cred := range i.creds {
		if cred.Type() == x509.CredType {
			return cred
		}
	}
	return nil
}

// GetECert returns the enrollment certificate signer for this identity
// Returns nil if the identity does not have a X509 credential
func (i *Identity) GetECert() *x509.Signer {
	for _, cred := range i.creds {
		if cred.Type() == x509.CredType {
			v, _ := cred.Val()
			if v != nil {
				s, _ := v.(*x509.Signer)
				return s
			}
		}
	}
	return nil
}

// GetTCertBatch returns a batch of TCerts for this identity
func (i *Identity) GetTCertBatch(req *api.GetTCertBatchRequest) ([]*x509.Signer, error) {
	reqBody, err := util.Marshal(req, "GetTCertBatchRequest")
	if err != nil {
		return nil, err
	}
	err = i.Post("tcert", reqBody, nil, nil)
	if err != nil {
		return nil, err
	}
	// Ignore the contents of the response for now.  They will be processed in the future when we need to
	// support the Go SDK.   We currently have Node and Java SDKs which process this and they are the
	// priority.
	return nil, nil
}

// Register registers a new identity
// @param req The registration request
func (i *Identity) Register(req *api.RegistrationRequest) (rr *api.RegistrationResponse, err error) {
	log.Debugf("Register %+v", req)
	if req.Name == "" {
		return nil, errors.New("Register was called without a Name set")
	}

	reqBody, err := util.Marshal(req, "RegistrationRequest")
	if err != nil {
		return nil, err
	}

	// Send a post to the "register" endpoint with req as body
	resp := &api.RegistrationResponse{}
	err = i.Post("register", reqBody, resp, nil)
	if err != nil {
		return nil, err
	}

	log.Debug("The register request completed successfully")
	return resp, nil
}

// RegisterAndEnroll registers and enrolls an identity and returns the identity
func (i *Identity) RegisterAndEnroll(req *api.RegistrationRequest) (*Identity, error) {
	if i.client == nil {
		return nil, errors.New("No client is associated with this identity")
	}
	rresp, err := i.Register(req)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("Failed to register %s", req.Name))
	}
	eresp, err := i.client.Enroll(&api.EnrollmentRequest{
		Name:   req.Name,
		Secret: rresp.Secret,
	})
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("Failed to enroll %s", req.Name))
	}
	return eresp.Identity, nil
}

// Reenroll reenrolls an existing Identity and returns a new Identity
// @param req The reenrollment request
func (i *Identity) Reenroll(req *api.ReenrollmentRequest) (*EnrollmentResponse, error) {
	log.Debugf("Reenrolling %s", util.StructToString(req))

	var (
		key    bccsp.Key
		csrPEM []byte
		err    error
	)
	if req.CSR != nil && req.CSR.KeyRequest != nil {
		if req.CSR.KeyRequest.ReuseKey {
			val, err := i.GetX509Credential().Val()
			if err != nil {
				return nil, err
			}
			key = val.(*x509.Signer).Key()
			csrPEM, key, err = i.client.GenCSRUsingKey(req.CSR, i.GetName(), key)
			if err != nil {
				return nil, err
			}
		}
	}

	if csrPEM == nil {
		csrPEM, key, err = i.client.GenCSR(req.CSR, i.GetName())
		if err != nil {
			return nil, err
		}
	}

	reqNet := &api.ReenrollmentRequestNet{
		CAName:   req.CAName,
		AttrReqs: req.AttrReqs,
	}

	// Get the body of the request
	if req.CSR != nil {
		reqNet.SignRequest.Hosts = req.CSR.Hosts
	}
	reqNet.SignRequest.Request = string(csrPEM)
	reqNet.SignRequest.Profile = req.Profile
	reqNet.SignRequest.Label = req.Label

	body, err := util.Marshal(reqNet, "SignRequest")
	if err != nil {
		return nil, err
	}
	var result common.EnrollmentResponseNet
	err = i.Post("reenroll", body, &result, nil)
	if err != nil {
		return nil, err
	}
	return i.client.newEnrollmentResponse(&result, i.GetName(), key)
}

// Revoke the identity associated with 'id'
func (i *Identity) Revoke(req *api.RevocationRequest) (*api.RevocationResponse, error) {
	log.Debugf("Entering identity.Revoke %+v", req)
	reqBody, err := util.Marshal(req, "RevocationRequest")
	if err != nil {
		return nil, err
	}
	var result revocationResponseNet
	err = i.Post("revoke", reqBody, &result, nil)
	if err != nil {
		return nil, err
	}
	log.Debugf("Successfully revoked certificates: %+v", req)
	crl, err := util.B64Decode(result.CRL)
	if err != nil {
		return nil, err
	}
	return &api.RevocationResponse{RevokedCerts: result.RevokedCerts, CRL: crl}, nil
}

// RevokeSelf revokes the current identity and all certificates
func (i *Identity) RevokeSelf() (*api.RevocationResponse, error) {
	name := i.GetName()
	log.Debugf("RevokeSelf %s", name)
	req := &api.RevocationRequest{
		Name: name,
	}
	return i.Revoke(req)
}

// GenCRL generates CRL
func (i *Identity) GenCRL(req *api.GenCRLRequest) (*api.GenCRLResponse, error) {
	log.Debugf("Entering identity.GenCRL %+v", req)
	reqBody, err := util.Marshal(req, "GenCRLRequest")
	if err != nil {
		return nil, err
	}
	var result genCRLResponseNet
	err = i.Post("gencrl", reqBody, &result, nil)
	if err != nil {
		return nil, err
	}
	log.Debugf("Successfully generated CRL: %+v", req)
	crl, err := util.B64Decode(result.CRL)
	if err != nil {
		return nil, err
	}
	return &api.GenCRLResponse{CRL: crl}, nil
}

// GetCRI gets Idemix credential revocation information (CRI)
func (i *Identity) GetCRI(req *api.GetCRIRequest) (*api.GetCRIResponse, error) {
	log.Debugf("Entering identity.GetCRI %+v", req)
	reqBody, err := util.Marshal(req, "GetCRIRequest")
	if err != nil {
		return nil, err
	}
	var result api.GetCRIResponse
	err = i.Post("idemix/cri", reqBody, &result, nil)
	if err != nil {
		return nil, err
	}
	log.Debugf("Successfully generated CRI: %+v", req)
	return &result, nil
}

// GetIdentity returns information about the requested identity
func (i *Identity) GetIdentity(id, caname string) (*api.GetIDResponse, error) {
	log.Debugf("Entering identity.GetIdentity %s", id)
	result := &api.GetIDResponse{}
	err := i.Get(fmt.Sprintf("identities/%s", id), caname, result)
	if err != nil {
		return nil, err
	}

	log.Debugf("Successfully retrieved identity: %+v", result)
	return result, nil
}

// GetAllIdentities returns all identities that the caller is authorized to see
func (i *Identity) GetAllIdentities(caname string, cb func(*json.Decoder) error) error {
	log.Debugf("Entering identity.GetAllIdentities")
	queryParam := make(map[string]string)
	queryParam["ca"] = caname
	err := i.GetStreamResponse("identities", queryParam, "result.identities", cb)
	if err != nil {
		return err
	}
	log.Debugf("Successfully retrieved identities")
	return nil
}

// AddIdentity adds a new identity to the server
func (i *Identity) AddIdentity(req *api.AddIdentityRequest) (*api.IdentityResponse, error) {
	log.Debugf("Entering identity.AddIdentity with request: %+v", req)
	if req.ID == "" {
		return nil, errors.New("Adding identity with no 'ID' set")
	}

	reqBody, err := util.Marshal(req, "addIdentity")
	if err != nil {
		return nil, err
	}

	// Send a post to the "identities" endpoint with req as body
	result := &api.IdentityResponse{}
	err = i.Post("identities", reqBody, result, nil)
	if err != nil {
		return nil, err
	}

	log.Debugf("Successfully added new identity '%s'", result.ID)
	return result, nil
}

// ModifyIdentity modifies an existing identity on the server
func (i *Identity) ModifyIdentity(req *api.ModifyIdentityRequest) (*api.IdentityResponse, error) {
	log.Debugf("Entering identity.ModifyIdentity with request: %+v", req)
	if req.ID == "" {
		return nil, errors.New("Name of identity to be modified not specified")
	}

	reqBody, err := util.Marshal(req, "modifyIdentity")
	if err != nil {
		return nil, err
	}

	// Send a put to the "identities" endpoint with req as body
	result := &api.IdentityResponse{}
	err = i.Put(fmt.Sprintf("identities/%s", req.ID), reqBody, nil, result)
	if err != nil {
		return nil, err
	}

	log.Debugf("Successfully modified identity '%s'", result.ID)
	return result, nil
}

// RemoveIdentity removes a new identity from the server
func (i *Identity) RemoveIdentity(req *api.RemoveIdentityRequest) (*api.IdentityResponse, error) {
	log.Debugf("Entering identity.RemoveIdentity with request: %+v", req)
	id := req.ID
	if id == "" {
		return nil, errors.New("Name of the identity to removed is required")
	}

	// Send a delete to the "identities" endpoint id as a path parameter
	result := &api.IdentityResponse{}
	queryParam := make(map[string]string)
	queryParam["force"] = strconv.FormatBool(req.Force)
	queryParam["ca"] = req.CAName
	err := i.Delete(fmt.Sprintf("identities/%s", id), result, queryParam)
	if err != nil {
		return nil, err
	}

	log.Debugf("Successfully removed identity: %s", id)
	return result, nil
}

// GetAffiliation returns information about the requested affiliation
func (i *Identity) GetAffiliation(affiliation, caname string) (*api.AffiliationResponse, error) {
	log.Debugf("Entering identity.GetAffiliation %+v", affiliation)
	result := &api.AffiliationResponse{}
	err := i.Get(fmt.Sprintf("affiliations/%s", affiliation), caname, result)
	if err != nil {
		return nil, err
	}
	log.Debugf("Successfully retrieved affiliation: %+v", result)
	return result, nil
}

// GetAllAffiliations returns all affiliations that the caller is authorized to see
func (i *Identity) GetAllAffiliations(caname string) (*api.AffiliationResponse, error) {
	log.Debugf("Entering identity.GetAllAffiliations")
	result := &api.AffiliationResponse{}
	err := i.Get("affiliations", caname, result)
	if err != nil {
		return nil, err
	}
	log.Debug("Successfully retrieved affiliations")
	return result, nil
}

// AddAffiliation adds a new affiliation to the server
func (i *Identity) AddAffiliation(req *api.AddAffiliationRequest) (*api.AffiliationResponse, error) {
	log.Debugf("Entering identity.AddAffiliation with request: %+v", req)
	if req.Name == "" {
		return nil, errors.New("Affiliation to add was not specified")
	}

	reqBody, err := util.Marshal(req, "addAffiliation")
	if err != nil {
		return nil, err
	}

	// Send a post to the "affiliations" endpoint with req as body
	result := &api.AffiliationResponse{}
	queryParam := make(map[string]string)
	queryParam["force"] = strconv.FormatBool(req.Force)
	err = i.Post("affiliations", reqBody, result, queryParam)
	if err != nil {
		return nil, err
	}

	log.Debugf("Successfully added new affiliation")
	return result, nil
}

// ModifyAffiliation renames an existing affiliation on the server
func (i *Identity) ModifyAffiliation(req *api.ModifyAffiliationRequest) (*api.AffiliationResponse, error) {
	log.Debugf("Entering identity.ModifyAffiliation with request: %+v", req)
	modifyAff := req.Name
	if modifyAff == "" {
		return nil, errors.New("Affiliation to modify was not specified")
	}

	if req.NewName == "" {
		return nil, errors.New("New affiliation not specified")
	}

	reqBody, err := util.Marshal(req, "modifyIdentity")
	if err != nil {
		return nil, err
	}

	// Send a put to the "affiliations" endpoint with req as body
	result := &api.AffiliationResponse{}
	queryParam := make(map[string]string)
	queryParam["force"] = strconv.FormatBool(req.Force)
	err = i.Put(fmt.Sprintf("affiliations/%s", modifyAff), reqBody, queryParam, result)
	if err != nil {
		return nil, err
	}

	log.Debugf("Successfully modified affiliation")
	return result, nil
}

// RemoveAffiliation removes an existing affiliation from the server
func (i *Identity) RemoveAffiliation(req *api.RemoveAffiliationRequest) (*api.AffiliationResponse, error) {
	log.Debugf("Entering identity.RemoveAffiliation with request: %+v", req)
	removeAff := req.Name
	if removeAff == "" {
		return nil, errors.New("Affiliation to remove was not specified")
	}

	// Send a delete to the "affiliations" endpoint with the affiliation as a path parameter
	result := &api.AffiliationResponse{}
	queryParam := make(map[string]string)
	queryParam["force"] = strconv.FormatBool(req.Force)
	queryParam["ca"] = req.CAName
	err := i.Delete(fmt.Sprintf("affiliations/%s", removeAff), result, queryParam)
	if err != nil {
		return nil, err
	}

	log.Debugf("Successfully removed affiliation")
	return result, nil
}

// GetCertificates returns all certificates that the caller is authorized to see
func (i *Identity) GetCertificates(req *api.GetCertificatesRequest, cb func(*json.Decoder) error) error {
	log.Debugf("Entering identity.GetCertificates, sending request: %+v", req)

	queryParam := make(map[string]string)
	queryParam["id"] = req.ID
	queryParam["aki"] = req.AKI
	queryParam["serial"] = req.Serial
	queryParam["revoked_start"] = req.Revoked.StartTime
	queryParam["revoked_end"] = req.Revoked.EndTime
	queryParam["expired_start"] = req.Expired.StartTime
	queryParam["expired_end"] = req.Expired.EndTime
	queryParam["notrevoked"] = strconv.FormatBool(req.NotRevoked)
	queryParam["notexpired"] = strconv.FormatBool(req.NotExpired)
	queryParam["ca"] = req.CAName
	err := i.GetStreamResponse("certificates", queryParam, "result.certs", cb)
	if err != nil {
		return err
	}

	log.Debugf("Successfully completed getting certificates request")
	return nil
}

// Store writes my identity info to disk
func (i *Identity) Store() error {
	if i.client == nil {
		return errors.New("An identity with no client may not be stored")
	}
	for _, cred := range i.creds {
		err := cred.Store()
		if err != nil {
			return err
		}
	}
	return nil
}

// Get sends a get request to an endpoint
func (i *Identity) Get(endpoint, caname string, result interface{}) error {
	req, err := i.client.newGet(endpoint)
	if err != nil {
		return err
	}
	if caname != "" {
		addQueryParm(req, "ca", caname)
	}
	err = i.addTokenAuthHdr(req, nil)
	if err != nil {
		return err
	}
	return i.client.SendReq(req, result)
}

// GetStreamResponse sends a request to an endpoint and streams the response
func (i *Identity) GetStreamResponse(endpoint string, queryParam map[string]string, stream string, cb func(*json.Decoder) error) error {
	req, err := i.client.newGet(endpoint)
	if err != nil {
		return err
	}
	if queryParam != nil {
		for key, value := range queryParam {
			if value != "" {
				addQueryParm(req, key, value)
			}
		}
	}
	err = i.addTokenAuthHdr(req, nil)
	if err != nil {
		return err
	}
	return i.client.StreamResponse(req, stream, cb)
}

// Put sends a put request to an endpoint
func (i *Identity) Put(endpoint string, reqBody []byte, queryParam map[string]string, result interface{}) error {
	req, err := i.client.newPut(endpoint, reqBody)
	if err != nil {
		return err
	}
	if queryParam != nil {
		for key, value := range queryParam {
			addQueryParm(req, key, value)
		}
	}
	err = i.addTokenAuthHdr(req, reqBody)
	if err != nil {
		return err
	}
	return i.client.SendReq(req, result)
}

// Delete sends a delete request to an endpoint
func (i *Identity) Delete(endpoint string, result interface{}, queryParam map[string]string) error {
	req, err := i.client.newDelete(endpoint)
	if err != nil {
		return err
	}
	if queryParam != nil {
		for key, value := range queryParam {
			addQueryParm(req, key, value)
		}
	}
	err = i.addTokenAuthHdr(req, nil)
	if err != nil {
		return err
	}
	return i.client.SendReq(req, result)
}

// Post sends arbitrary request body (reqBody) to an endpoint.
// This adds an authorization header which contains the signature
// of this identity over the body and non-signature part of the authorization header.
// The return value is the body of the response.
func (i *Identity) Post(endpoint string, reqBody []byte, result interface{}, queryParam map[string]string) error {
	req, err := i.client.newPost(endpoint, reqBody)
	if err != nil {
		return err
	}
	if queryParam != nil {
		for key, value := range queryParam {
			addQueryParm(req, key, value)
		}
	}
	err = i.addTokenAuthHdr(req, reqBody)
	if err != nil {
		return err
	}
	return i.client.SendReq(req, result)
}

func (i *Identity) addTokenAuthHdr(req *http.Request, body []byte) error {
	log.Debug("Adding token-based authorization header")
	var token string
	var err error
	for _, cred := range i.creds {
		token, err = cred.CreateToken(req, body)
		if err != nil {
			return errors.WithMessage(err, "Failed to add token authorization header")
		}
		break
	}
	req.Header.Set("authorization", token)
	return nil
}
