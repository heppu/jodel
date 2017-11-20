package jodel

import (
	"net/http"
	"testing"
)

var account = &JodelAccount{
	Location: Location{
		Accuracy: 0.0,
		City:     "Munich",
		Country:  "DE",
		Name:     "Munich",
		Coordinates: Coordinates{
			Lat: 48.148434,
			Lng: 11.567867,
		},
	},
	Client: &http.Client{},
}

func TestInitAccount(t *testing.T) {
	if err := account.InitAccount(); err != nil {
		t.Error(err)
	}
}

func TestRefreshAccessToken(t *testing.T) {
	if err := account.RefreshAccessToken(); err != nil {
		t.Error(err)
	}
}

func TestVerify(t *testing.T) {
	if err := account.Verify(); err != nil {
		t.Error(err)
	}
}

func TestGetPosts(t *testing.T) {
	if _, err := account.GetPosts(CategoryMine, PostsRecent, 0, 60, ""); err != nil {
		t.Error(err)
	}
}
