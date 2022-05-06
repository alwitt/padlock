package apis

import (
	"net/http"

	"github.com/gorilla/mux"
)

// MethodHandlers DICT of method-endpoint handler
type MethodHandlers map[string]http.HandlerFunc

// registerPathPrefix registers new method handler for a path prefix
func registerPathPrefix(parent *mux.Router, prefix string, handler MethodHandlers) *mux.Router {
	router := parent.PathPrefix(prefix).Subrouter()
	for method, handler := range handler {
		router.Methods(method).Path("").HandlerFunc(handler)
	}
	return router
}
