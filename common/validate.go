package common

import (
	"reflect"

	"github.com/go-playground/validator/v10"
)

// CustomFieldValidator support class for running custom validation of fields
type CustomFieldValidator interface {
	/*
		RegisterWithValidator register with the validator this customer validation support

		 @param v *validator.Validate - the validator to register against
		 @return whether successful
	*/
	RegisterWithValidator(v *validator.Validate) error

	/*
		ValidateUserID custom user ID validation function

		 @param fl validator.FieldLevel - the field to validate
		 @return whether is valid
	*/
	ValidateUserID(fl validator.FieldLevel) bool

	/*
		ValidateUserName custom user name validation function

		 @param fl validator.FieldLevel - the field to validate
		 @return whether is valid
	*/
	ValidateUserName(fl validator.FieldLevel) bool

	/*
		ValidatePersonalName custom surname and family name validation function

		 @param fl validator.FieldLevel - the field to validate
		 @return whether is valid
	*/
	ValidatePersonalName(fl validator.FieldLevel) bool

	/*
		ValidateRoleName custom role name validation function

		 @param fl validator.FieldLevel - the field to validate
		 @return whether is valid
	*/
	ValidateRoleName(fl validator.FieldLevel) bool
}

// customValidatorImpl support class for running custom validation of fields
type customValidatorImpl struct {
	userIDMatcher       RegexCheck
	usernameMatcher     RegexCheck
	personalNameMatcher RegexCheck
	roleNameMatcher     RegexCheck
}

/*
GetCustomFieldValidator get new CustomFieldValidator instance

 @param userIDRegex string - usr ID validation regex
 @param usernameRegex string - username validation regex
 @param nameRegex string - personal name validation regex
 @param roleNameRegex string - role name validation regex
 @return new CustomFieldValidator instance
*/
func GetCustomFieldValidator(
	userIDRegex string, usernameRegex string, nameRegex string, roleNameRegex string,
) (CustomFieldValidator, error) {
	idMatch, err := NewRegexCheck(userIDRegex)
	if err != nil {
		return nil, err
	}
	unMatch, err := NewRegexCheck(usernameRegex)
	if err != nil {
		return nil, err
	}
	nameMatch, err := NewRegexCheck(nameRegex)
	if err != nil {
		return nil, err
	}
	roleMatch, err := NewRegexCheck(roleNameRegex)
	if err != nil {
		return nil, err
	}
	return &customValidatorImpl{
		userIDMatcher:       idMatch,
		usernameMatcher:     unMatch,
		personalNameMatcher: nameMatch,
		roleNameMatcher:     roleMatch,
	}, nil
}

/*
RegisterWithValidator register with the validator this customer validation support

 @param v *validator.Validate - the validator to register against
 @return whether successful
*/
func (m *customValidatorImpl) RegisterWithValidator(v *validator.Validate) error {
	if err := v.RegisterValidation("user_id", m.ValidateUserID); err != nil {
		return err
	}
	if err := v.RegisterValidation("username", m.ValidateUserName); err != nil {
		return err
	}
	if err := v.RegisterValidation("personal_name", m.ValidatePersonalName); err != nil {
		return err
	}
	if err := v.RegisterValidation("role_name", m.ValidateRoleName); err != nil {
		return err
	}
	return nil
}

/*
ValidateUserID custom user ID validation function

 @param fl validator.FieldLevel - the field to validate
 @return whether is valid
*/
func (m *customValidatorImpl) ValidateUserID(fl validator.FieldLevel) bool {
	if fl.Field().Kind() != reflect.String {
		return false
	}
	asString := fl.Field().String()
	valid, err := m.userIDMatcher.Match([]byte(asString))
	if err != nil {
		return false
	}
	return valid
}

/*
ValidateUserName custom user name validation function

 @param fl validator.FieldLevel - the field to validate
 @return whether is valid
*/
func (m *customValidatorImpl) ValidateUserName(fl validator.FieldLevel) bool {
	if fl.Field().Kind() != reflect.String {
		return false
	}
	asString := fl.Field().String()
	valid, err := m.usernameMatcher.Match([]byte(asString))
	if err != nil {
		return false
	}
	return valid
}

/*
ValidatePersonalName custom surname and family name validation function

 @param fl validator.FieldLevel - the field to validate
 @return whether is valid
*/
func (m *customValidatorImpl) ValidatePersonalName(fl validator.FieldLevel) bool {
	if fl.Field().Kind() != reflect.String {
		return false
	}
	asString := fl.Field().String()
	valid, err := m.personalNameMatcher.Match([]byte(asString))
	if err != nil {
		return false
	}
	return valid
}

/*
ValidateRoleName custom role name validation function

 @param fl validator.FieldLevel - the field to validate
 @return whether is valid
*/
func (m *customValidatorImpl) ValidateRoleName(fl validator.FieldLevel) bool {
	if fl.Field().Kind() != reflect.String {
		return false
	}
	asString := fl.Field().String()
	valid, err := m.roleNameMatcher.Match([]byte(asString))
	if err != nil {
		return false
	}
	return valid
}
