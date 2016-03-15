package ntlm

import (
	"encoding/base64"
	"io"
	"io/ioutil"
	"net/http"
)

func DoNtlmSSPIAuth(httpClient *http.Client, request *http.Request) (*http.Response, error) {
    
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
        
        auth, authOk := getDefaultCredentialsAuth() 
        if authOk {
            negotiateMessageBytes, err := auth.InitialBytes()
            if err != nil {
                return nil, err
            }
            defer auth.Free()
            
            negotiateReq, err := cloneRequest(request)
            if err != nil {
                return nil, err
            }
            
            challengeMessage, err := sendNegotiateRequest(httpClient, negotiateReq, negotiateMessageBytes)
            if err != nil {
                return nil, err
            }
            
            challengeReq, err := cloneRequest(request)
            if err != nil {
                return nil, err
            }
            
            responseBytes, err := auth.NextBytes(challengeMessage)
            
            res, err := sendChallengeRequest(httpClient, challengeReq, responseBytes)
            if err != nil {
                return nil, err
            }
            
            return res, nil
        }
    }   
     
    return res, nil
}

func sendNegotiateRequest(httpClient *http.Client, request *http.Request, negotiateMessageBytes []byte) ([]byte, error) {
    negotiateMsg :=  base64.StdEncoding.EncodeToString(negotiateMessageBytes)
    
    request.Header.Add("Authorization", "NTLM "+negotiateMsg)
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

func sendChallengeRequest(httpClient *http.Client, request *http.Request, challengeBytes []byte) (*http.Response, error) {
	authMsg := base64.StdEncoding.EncodeToString(challengeBytes)
	request.Header.Add("Authorization", "NTLM "+authMsg)
	return httpClient.Do(request)
}