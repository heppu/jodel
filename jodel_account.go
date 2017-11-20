package jodel

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/heppu/jodel/android"
)

const (
	API_URL     = "https://api.go-tellm.com/api"
	CLIENT_ID   = "81e8a76e-1e02-4d17-9ba0-8a7020261b26"
	SECRET      = "tnutBKGDbpBzBbNRmIoxTLDPHIdVcnRQBRsXZIUm"
	VERSION     = "4.67.1"
	USER_AGENT  = "Jodel/" + VERSION + " Dalvik/2.1.0 (Linux; U; Android 5.1.1; )"
	TIME_FORMAT = "2006-01-02T15:04:05Z"
)

type PostOrder string

const (
	PostsRecent    PostOrder = ""
	PostsPopular   PostOrder = "popular"
	PostsDiscussed PostOrder = "discussed"
	PostsPinned    PostOrder = "pinned"
	PostsReplies   PostOrder = "replies"
	PostsVotes     PostOrder = "votes"
)

type PostCategory string

const (
	CategoryMine     PostCategory = "mine"
	CategoryHashtag  PostCategory = "hashtag"
	CategoryChannel  PostCategory = "channel"
	CategoryLocation PostCategory = "location"
)

type JodelAccount struct {
	DeviceUID string
	Client    *http.Client
	TokenData
	Location
	android.AndroidAccount
}

type Coordinates struct {
	Lat float64 `json:"lat"`
	Lng float64 `json:"lng"`
}

type Location struct {
	Accuracy    float64 `json:"loc_accuracy"`
	City        string  `json:"city"`
	Country     string  `json:"country"`
	Name        string  `json:"name"`
	Coordinates `json:"loc_coordinates"`
}

type UserPayload struct {
	ClientID  string `json:"CLIENT_ID"`
	DeviceUID string `json:"device_uid"`
	Location  `json:"location"`
}

type RefreshAccessTokenPayload struct {
	ClientID     string `json:"CLIENT_ID"`
	DistinctID   string `json:"distinct_id"`
	RefreshToken string `json:"refresh_token"`
}

type TokenData struct {
	AccessToken    string `json:"access_token"`
	RefreshToken   string `json:"refresh_token"`
	TokenType      string `json:"token_type"`
	ExpiresIn      int    `json:"expires_in"`
	ExpirationDate int    `json:"expiration_date"`
	DistinctID     string `json:"distinct_id"`
	Returning      bool   `json:"returning"`
}

type Post struct {
	ID string `json:"id"`
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

// Account functions
func (j *JodelAccount) InitAccount() (err error) {
	if j.DeviceUID == "" {
		j.DeviceUID = generateID()
	}

	if j.TokenData.AccessToken != "" {
		return
	}

	var payload []byte
	if payload, err = json.Marshal(&UserPayload{
		ClientID:  CLIENT_ID,
		DeviceUID: j.DeviceUID,
		Location:  j.Location,
	}); err != nil {
		return
	}

	if err = j.post("/v2/users", bytes.NewBuffer(payload), &j.TokenData); err != nil {
		return
	}
	return
}

func (j *JodelAccount) RefreshAccessToken() (err error) {
	var payload []byte
	if payload, err = json.Marshal(&RefreshAccessTokenPayload{
		ClientID:     CLIENT_ID,
		DistinctID:   j.TokenData.DistinctID,
		RefreshToken: j.TokenData.RefreshToken,
	}); err != nil {
		return
	}

	if err = j.post("/v2/users/refreshToken", bytes.NewBuffer(payload), &j.TokenData); err != nil {
		return
	}

	return
}

func (j *JodelAccount) Verify() (err error) {
	return
}

func (j *JodelAccount) CreatePost(post Post) (err error) {
	var payload []byte
	if payload, err = json.Marshal(&post); err != nil {
		return
	}
	err = j.post("/v3/posts", bytes.NewBuffer(payload), nil)
	return
}

func (j *JodelAccount) GetPosts(category PostCategory, order PostOrder, skip, limit uint, categoryData string) (posts []Post, err error) {
	var query url.Values
	query.Add("lat", fmt.Sprintf("%f", j.Location.Lat))
	query.Add("lng", fmt.Sprintf("%f", j.Location.Lng))
	query.Add("skip", fmt.Sprintf("%d", skip))
	query.Add("limit", fmt.Sprintf("%d", limit))

	apiVersion := "v2"
	if category == CategoryHashtag || category == CategoryChannel {
		query.Add(string(category), categoryData)
		apiVersion = "v3"
	}

	u := fmt.Sprintf("/%s/posts/%s%s", apiVersion, category, order, query.Encode())

	posts = make([]Post, 0)
	err = j.get(u, &posts)
	return
}

func (j *JodelAccount) GetPost(id string) (post Post, err error) {
	var query url.Values
	query.Add("details", "true")

	u := fmt.Sprintf("/v3/posts/%s/details%s", id, query.Encode())

	post = Post{}
	err = j.get(u, &post)
	return
}

func (j *JodelAccount) Upvote(id string) (err error) {
	u := fmt.Sprintf("/v3/posts/%s/upvote", id)
	err = j.put(u, nil, nil)
	return
}

func (j *JodelAccount) Downvote(id string) (err error) {
	u := fmt.Sprintf("/v3/posts/%s/downvote", id)
	err = j.put(u, nil, nil)
	return
}

// HTTP functions
func (j *JodelAccount) post(url string, payload io.Reader, data interface{}) error {
	return j.send(http.MethodPost, url, payload, data)
}

func (j *JodelAccount) put(url string, payload io.Reader, data interface{}) error {
	return j.send(http.MethodPut, url, payload, data)
}

func (j *JodelAccount) get(url string, data interface{}) error {
	return j.send(http.MethodGet, url, nil, data)
}

func (j *JodelAccount) send(method, url string, payload io.Reader, data interface{}) (err error) {
	var req *http.Request
	if req, err = http.NewRequest(method, API_URL+url, payload); err != nil {
		return
	}

	if err = j.signRequest(req); err != nil {
		return
	}

	var res *http.Response
	if res, err = j.Client.Do(req); err != nil {
		return
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		err = fmt.Errorf("%d : %s", res.StatusCode, res.Status)
		return
	}

	if data != nil {
		if err = json.NewDecoder(res.Body).Decode(data); err != nil {
			return
		}
	}
	return
}

func (j *JodelAccount) signRequest(req *http.Request) (err error) {
	var params sort.StringSlice
	for key, values := range req.URL.Query() {
		for _, value := range values {
			params = append(params, key+"%"+value)
		}
	}
	params.Sort()
	paramsString := strings.Join(params, "%")

	var buf []byte
	if req.Body != nil {
		if buf, err = ioutil.ReadAll(req.Body); err != nil {
			return
		}
		req.Body = ioutil.NopCloser(bytes.NewBuffer(buf))
	}

	timestamp := time.Now().UTC().Format(TIME_FORMAT)
	message := fmt.Sprintf("%s%%%s%%%d%%%s%%%s%%%s%%%s%%%s", req.Method, req.URL.Host, 443, req.URL.Path, j.TokenData.AccessToken, timestamp, paramsString, buf)
	mac := hmac.New(sha1.New, []byte(SECRET))
	mac.Write([]byte(message))
	signature := fmt.Sprintf("%X", mac.Sum(nil))

	req.Header.Set("X-Authorization", "HMAC "+string(signature))
	req.Header.Set("X-Client-Type", "android_"+VERSION)
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Api-Version", "0.2")
	req.Header.Set("User-Agent", USER_AGENT)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	if j.TokenData.AccessToken != "" {
		req.Header.Set("Authorization", j.TokenData.AccessToken)
	}

	return
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func generateID() string {
	b := make([]rune, 64)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
