package http

import (
    "crypto/tls"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
    "strings"
)

type Response interface {
    IsSuccess() bool
    GetMessage() string
}

type ResponseImpl struct {
    Success bool   `json:"success"`
    Message string `json:"msg"`
    //Data
}

func (r ResponseImpl) IsSuccess() bool {
    return r.Success
}

func (r ResponseImpl) GetMessage() string {
    return r.Message
}

func init() {
    http.DefaultClient.Transport = &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true,
        },
    }
}

type AuthInfo struct {
    User string
    Pass string
}

type RequestConfig struct {
    Method      string
    ContentType string // default application/json
    AuthType    string // "BasicAuth"
    AuthInfo
}

 func CRequest(url, data string, config *RequestConfig, response Response) error {    
    if config.Method == "" {
        config.Method = "POST"
    }
    req, err := http.NewRequest(config.Method, url, strings.NewReader(data))
    if err != nil {
        return err
    }
    if config.ContentType != "" {
        req.Header.Set("Content-Type", config.ContentType)
    } else {
        req.Header.Set("Content-Type", "application/json")
    }

    if config.AuthType == "BasicAuth" {
        req.SetBasicAuth(config.User, config.Pass)
    }
    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return err
    }

    return toResponse(resp, response)
}

func Request(url string, response Response) error {
    resp, err := http.Get(url)
    if err != nil {
        return err
    }

    return toResponse(resp, response)
}

func toResponse(resp *http.Response, response Response) error {
    b, err := ioutil.ReadAll(resp.Body)
    resp.Body.Close()
    err = json.Unmarshal(b, response)
    logger.Debugf("response:%s", b)
    if err != nil {
        logger.Errorf("parse json err:%v, json:%s", err, b)
        return err
    }
    //log.Printf("re o:%v", response);
    if !response.IsSuccess() {
        logger.Debugf("response:%s", b)
        msg := response.GetMessage()
        if msg == "" {
            msg = "response:" + string(b)
        }
        return fmt.Errorf("request err:%s", msg)
    }

    return nil
}

func GetRemoteIP(r *http.Request) string {
    if ip := r.Header.Get("X-Forward-For"); ip != "" {
        return ip
    }
    if ip := r.Header.Get("X-Real-IP"); ip != "" {
        return ip
    }

    ip := strings.Split(r.RemoteAddr, ":")[0]

    if ip == "::1" {
        ip = "127.0.0.1"
    }

    return ip
}
