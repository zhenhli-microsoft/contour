package contour

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
)

type PemData struct {
	Pem string `json:"pem"`
}

type logger interface {
	Debugf(string, ...interface{})
	Infof(string, ...interface{})
	Warnf(string, ...interface{})
	Errorf(string, ...interface{})
	Fatalf(string, ...interface{})
}

// GetPemDataFromCertServer returns []bytes format of certificates via HTTP connection
// to control plane server.
func GetPemDataFromCertServer(certServerAddr string, certServerPort int, path string, log logger) ([]byte, error) {
	endpoint := "http://" + certServerAddr + ":" + strconv.Itoa(certServerPort) + "/" + path
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		log.Errorf("Error Occured. %+v", err)
		return nil, err
	}
	// use http.DefaultClient to send request with retry mechanism
	var response *http.Response
	var pem PemData
	log.Infof("Attempting to get certificates from certificate loader")
	err = retry.OnError(wait.Backoff{
		Steps:    5,
		Duration: 1 * time.Second,
		Factor:   1.0,
		Jitter:   0.1,
	}, func(err error) bool {
		return true
	}, func() error {
		log.Infof("Attempting to call certificate loader")
		var err error
		response, err = http.DefaultClient.Do(req)
		if err != nil {
			log.Errorf("Failed to call certificate loader.")
			return err
		}
		// Close the connection to reuse it
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			var body []byte
			body, err = ioutil.ReadAll(response.Body)
			bodyString := string(body)
			if err != nil {
				bodyString = fmt.Sprintf("error reading response body: %+v", err)
			}
			err = fmt.Errorf("got %+v when seding request to endpoint %+v, response body: %+v", response.StatusCode, endpoint, bodyString)
			log.Errorf("Error Occured. %+v", err)
			return err
		}
		err = json.NewDecoder(response.Body).Decode(&pem)
		if err != nil {
			log.Errorf("Couldn't parse response body to json: %+v", err)
			return err
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}
	return []byte(pem.Pem), nil
}
