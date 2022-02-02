package models

import (
	"time"
)

// UserConfig is user create / update parameters
type UserConfig struct {
	// UserID is the user's ID
	UserID string `json:"user_id" gorm:"uniqueIndex" validate:"required,user_id"`
	// UserName is the username
	Username *string `json:"username,omitempty" validate:"omitempty,username"`
	// Email is the user's email
	Email *string `json:"email,omitempty" validate:"omitempty,email"`
	// FirstName is the user's first name / given name
	FirstName *string `json:"first_name,omitempty" validate:"omitempty,personal_name"`
	// LastName is the user's last name / surname / family name
	LastName *string `json:"last_name,omitempty" validate:"omitempty,personal_name"`
}

// UserInfo is information regarding a user
type UserInfo struct {
	// CreatedAt is when the user entry is created
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when the user entry was last updated
	UpdatedAt time.Time `json:"updated_at"`
	UserConfig
}

// UserDetails is information regarding a user with additional information
type UserDetails struct {
	UserInfo
	// Roles are the roles associated with the user
	Roles []string `json:"roles"`
}
