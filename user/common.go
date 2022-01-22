package user

/*
Permission describe an allowed action.

If a user only has permission 'read_only', then this user can only perform 'read_only' actions.
*/
type Permission string

// Role describes an abstract user which have a set of permissions
type Role interface {
	/*
		Name returns the name of the role

		 @return the name of the role
	*/
	Name() string

	/*
		Permissions returns the list of permissions assigned to this role

		 @return the list of permissions
	*/
	Permissions() []Permission
}

// User describes a user which have a set of associated roles
type User interface {
	/*
		Name returns the ID of the user

		 @return the ID of the user
	*/
	ID() string

	/*
		Roles returns the list of roles assigned to this user

		 @return the list of roles
	*/
	Roles() []Role

	/*
		Permissions returns the list of all permissions given to this user

		 @return the list of permissions
	*/
	Permissions() []Permission
}
