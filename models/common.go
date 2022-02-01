package models

import (
	"time"
)

/*
Permission describe an allowed action.

If a user only has permission 'read_only', then this user can only perform 'read_only' actions.
*/
type Permission string

// UserConfig is user create / update parameters
type UserConfig struct {
	// UserID is the user's ID
	UserID string `json:"user_id" gorm:"uniqueIndex" validate:"required,alphanum|uuid_rfc4122"`
	// UserName is the username
	Username *string `json:"username,omitempty" validate:"omitempty,alphanum|uuid_rfc4122"`
	// Email is the user's email
	Email *string `json:"email,omitempty" validate:"omitempty,email"`
	// FirstName is the user's first name / given name
	FirstName *string `json:"first_name,omitempty" validate:"omitempty,alpha"`
	// LastName is the user's last name / surname / family name
	LastName *string `json:"last_name,omitempty" validate:"omitempty,alpha"`
}

// UserInfo is information regarding a user
type UserInfo struct {
	UserConfig
	// CreatedAt is when the user entry is created
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when the user entry was last updated
	UpdatedAt time.Time `json:"updated_at"`
}

// UserDetails is information regarding a user with additional information
type UserDetails struct {
	UserInfo
	// Roles are the roles associated with the user
	Roles []string `json:"roles"`
}
