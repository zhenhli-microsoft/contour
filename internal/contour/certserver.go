package contour

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
)

// ContourCertFromCertServer returns []bytes format of certificates via HTTP connection
// to control plane server.
func ContourCertFromCertServer(certServerAddr string, certServerPort int, path string) ([]byte, error) {
	endpoint := "http://" + certServerAddr + ":" + strconv.Itoa(certServerPort) + "/" + path
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		log.Fatalf("Error Occured. %+v", err)
		return nil, err
	}
	// use http.DefaultClient to send request with retry mechanism
	var response *http.Response
	var body []byte
	log.Printf("Attempting to get certificates for a new envoy client")
	err = retry.OnError(wait.Backoff{
		Steps:    5,
		Duration: 1 * time.Second,
		Factor:   1.0,
		Jitter:   0.1,
	}, func(err error) bool {
		return true
	}, func() error {
		log.Printf("Attempting to connect to certificate loader")
		var err error
		response, err = http.DefaultClient.Do(req)
		if err != nil {
			log.Fatalf("Failed to call certificate loader.")
			return err
		}
		// Close the connection to reuse it
		defer response.Body.Close()

		// Let's check if the work actually is done
		// We have seen inconsistencies even when we get 200 OK response
		body, err = ioutil.ReadAll(response.Body)
		if err != nil {
			log.Fatalf("Couldn't parse response body. %+v", err)
			return err
		}
		if response.StatusCode != http.StatusOK {
			err = fmt.Errorf("got %+v when seding request to endpoint %+v, response body: %+v", response.StatusCode, endpoint, body)
			log.Fatalf("Error Occured. %+v", err)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return body, nil
}
