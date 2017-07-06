package user

type Client struct {
	Name   string
	Groups string
	Mail   string
}

type serial struct {
	expired bool
	revoked bool
}
