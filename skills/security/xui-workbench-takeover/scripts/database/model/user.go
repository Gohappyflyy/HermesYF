package model

// User mirrors 3x-ui v2's database/model.User so gob records the same
// registered type name (github.com/mhsanaei/3x-ui/v2/database/model.User).
type User struct {
	Id       int
	Username string
	Password string
}
