package android

type AndroidAccount struct {
	AndroidID     string
	SecurityToken string
}

func NewAccount() *AndroidAccount {
	return &AndroidAccount{
		AndroidID:     "dummy-id",
		SecurityToken: "dummy-token",
	}
}
