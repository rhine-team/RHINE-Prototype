// This file holds some common code related to HTTP
// used by different entities

package common

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

func setUpClient(cert []byte) *http.Client {
	CAPool := x509.NewCertPool()
	CAPool.AppendCertsFromPEM(cert)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: CAPool}}}
	return client
}

func SetUpClientFromFile(certFile string) (*http.Client, error) {
	cert, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	return setUpClient(cert), nil
}

func ReadHTTPBody(reqStruct interface{}, r io.Reader) ([]byte, error){
	body, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(body, reqStruct)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func LogResponse(msg string, resp *http.Response) {
	log.Println(msg)
	log.Println("Response Status:", resp.Status)
	log.Println("Response Headers:", resp.Header)
	body, err := ioutil.ReadAll(resp.Body)
	LogError("failed to read response body: %s", err)
	if len(body) > 0 {
		log.Println("Response Body:", string(body))
	}
}

func SendHTTPError(status int, err error, w http.ResponseWriter) {
	errMsg := fmt.Errorf(http.StatusText(status) + ": %s", err)
	http.Error(w, errMsg.Error(), status)
}

func SendResponseBack(resp interface{}, w http.ResponseWriter) error {
	jsonMsg, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	_, err = w.Write(jsonMsg)
	if err != nil {
		return err
	}

	return nil
}

func PostAndParseResp(req interface{}, url string, client *http.Client) (*http.Response, int, error) {
	jsonReq, err := json.Marshal(req)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to marshal request: %s", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonReq))
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to create new HTTP request: %s", err)
	}

	httpReq.Header.Set(ContentTypeHeader, AppJsonHeader)

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, http.StatusServiceUnavailable, fmt.Errorf("failed to contact client: %s", err)
	}

	return resp, resp.StatusCode, nil
}

func CheckRespStatus(resp *http.Response) error {
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		return errors.New(string(body))
	}

	return nil
}