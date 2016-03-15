package ntlm

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"github.com/ThomsonReutersEikon/go-ntlm/ntlm"
)

var (
    ntlmSession ntlm.ClientSession 
)

func ntlmClientSession(creds Creds) (ntlm.ClientSession, error) {

    if ntlmSession != nil {
		return ntlmSession, nil
	}
	
	splits := strings.Split(creds.username, "\\")

	if len(splits) != 2 {
		errorMessage := fmt.Sprintf("Your user name must be of the form DOMAIN\\user. It is currently %s", creds.username, "string")
		return nil, errors.New(errorMessage)
	}

	session, err := ntlm.CreateClientSession(ntlm.Version2, ntlm.ConnectionOrientedMode)

	if err != nil {
		return nil, err
	}

	session.SetUserInfo(splits[1], creds.password, strings.ToUpper(splits[0]))
	
    ntlmSession = session
    return session, nil
}

func DoNTLMRequest(httpClient *http.Client, request *http.Request, username string, password string, 
    retry bool) (*http.Response, error) {

    if password == "" {
        //delegate it to SSPI authenticator
        return DoNtlmSSPIAuth(httpClient, request)
    }
	
    handshakeReq, err := cloneRequest(request)
	if err != nil {
		return nil, err
	}
    
	res, err := httpClient.Do(handshakeReq)
	if err != nil && res == nil {
		return nil, err
	}

	//If the status is 401 then we need to re-authenticate, otherwise it was successful
	if res.StatusCode == 401 {
    
        negotiateReq, err := cloneRequest(request)
		if err != nil {
			return nil, err
		}
        
        challengeMessage, err := negotiate(httpClient, negotiateReq, ntlmNegotiateMessage)
        if err != nil {
            return nil, err
        }

        challengeReq, err := cloneRequest(request)
        if err != nil {
            return nil, err
        }

        creds := Creds{username: username, password: password}
        res, err := challenge(httpClient, challengeReq, challengeMessage, creds)
        if err != nil {
            return nil, err
        }
        
        //If the status is 401 then we need to re-authenticate
        if res.StatusCode == 401 && retry == true {
            return DoNTLMRequest(httpClient, challengeReq, username, password, false)
        }
        
        return res, nil
	}
	return res, nil
}

func negotiate(httpClient *http.Client, request *http.Request, message string) ([]byte, error) {
	request.Header.Add("Authorization", message)
	res, err := httpClient.Do(request)

	if res == nil && err != nil {
		return nil, err
	}

	io.Copy(ioutil.Discard, res.Body)
	res.Body.Close()

	ret, err := parseChallengeResponse(res)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func challenge(httpClient *http.Client, request *http.Request, challengeBytes []byte, creds Creds) (*http.Response, error) {
	challenge, err := ntlm.ParseChallengeMessage(challengeBytes)
	if err != nil {
		return nil, err
	}

	session, err := ntlmClientSession(creds)
	if err != nil {
		return nil, err
	}

	session.ProcessChallengeMessage(challenge)
	authenticate, err := session.GenerateAuthenticateMessage()
	if err != nil {
		return nil, err
	}

	authMsg := base64.StdEncoding.EncodeToString(authenticate.Bytes())
	request.Header.Add("Authorization", "NTLM "+authMsg)
	return httpClient.Do(request)
}

const ntlmNegotiateMessage = "NTLM TlRMTVNTUAABAAAAB7IIogwADAAzAAAACwALACgAAAAKAAAoAAAAD1dJTExISS1NQUlOTk9SVEhBTUVSSUNB"