package googleoauth2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	types "github.com/Leapforce-nl/go_types"
)

func (oa *OAuth2) GetHttpClient() (*http.Client, error) {
	/*err := oa.Wait()
	if err != nil {
		return nil, err
	}*/

	err := oa.ValidateToken()
	if err != nil {
		return nil, err
	}

	return new(http.Client), nil
}

func (oa *OAuth2) Get(url string, model interface{}) error {
	client, errClient := oa.GetHttpClient()
	if errClient != nil {
		return errClient
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		//fmt.Println("errNewRequest")
		return err
	}

	oa.LockToken()

	// Add authorization token to header
	var bearer = "Bearer " + oa.Token.AccessToken
	req.Header.Add("Authorization", bearer)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	// Send out the HTTP request
	res, err := client.Do(req)
	oa.UnlockToken()
	if err != nil {
		//fmt.Println("errDo")
		return err
	}

	// Check HTTP StatusCode
	if res.StatusCode < 200 || res.StatusCode > 299 {
		//fmt.Println("ERROR in Post:", url)
		//fmt.Println(url)
		//fmt.Println("StatusCode", res.StatusCode)
		//fmt.Println(oa.Token.AccessToken)
		return oa.PrintError(res)
	}

	defer res.Body.Close()

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	err = json.Unmarshal(b, &model)
	if err != nil {
		//fmt.Println("errUnmarshal1")
		return oa.PrintError(res)
	}

	return nil
}

func (oa *OAuth2) Post(url string, values map[string]string, model interface{}) error {
	buf := new(bytes.Buffer)
	json.NewEncoder(buf).Encode(values)

	return oa.PostBuffer(url, buf, model)
}

func (oa *OAuth2) PostBytes(url string, b []byte, model interface{}) error {
	return oa.PostBuffer(url, bytes.NewBuffer(b), model)
}

func (oa *OAuth2) PostBuffer(url string, buf *bytes.Buffer, model interface{}) error {
	client, errClient := oa.GetHttpClient()
	if errClient != nil {
		return errClient
	}

	req, err := http.NewRequest(http.MethodPost, url, buf)
	if err != nil {
		//fmt.Println("errNewRequest")
		return err
	}

	oa.LockToken()

	// Add authorization token to header
	var bearer = "Bearer " + oa.Token.AccessToken
	req.Header.Add("Authorization", bearer)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	// Send out the HTTP request
	res, err := client.Do(req)
	oa.UnlockToken()
	if err != nil {
		//fmt.Println("errDo")
		return err
	}

	// Check HTTP StatusCode
	if res.StatusCode < 200 || res.StatusCode > 299 {
		//fmt.Println("ERROR in Post:", url)
		//fmt.Println(url)
		//fmt.Println("StatusCode", res.StatusCode)
		//fmt.Println(oa.Token.AccessToken)
		return oa.PrintError(res)
	}

	defer res.Body.Close()

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	err = json.Unmarshal(b, &model)
	if err != nil {
		//fmt.Println("errUnmarshal1")
		return oa.PrintError(res)
	}

	return nil
}

func (oa *OAuth2) PrintError(res *http.Response) error {
	fmt.Println("Status", res.Status)

	/*b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		//fmt.Println("errUnmarshal1")
		return err
	}

	ee := GoogleSearchControlError{}

	err = json.Unmarshal(b, &ee)
	if err != nil {
		//fmt.Println("errUnmarshal1")
		return err
	}*/

	//message := fmt.Sprintf("Server returned statuscode %v, error:%s", res.StatusCode, ee.Err.Message)
	message := fmt.Sprintf("Server returned statuscode %v", res.StatusCode)
	return &types.ErrorString{message}
}
