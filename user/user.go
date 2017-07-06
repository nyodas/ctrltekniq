package user

type Client struct {
	Name   string
	Groups string
	Mail   string
}

type Serial struct {
	Expired bool
	Revoked bool
}
