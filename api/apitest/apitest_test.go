package apitest_test

import (
	"testing"

	"github.com/IronGall-dev/irongall-client/api/apitest"
)

func TestTheDescriptionIsValidOpenAPI(t *testing.T) {
	if _, err := apitest.Validator(); err != nil {
		t.Fatal(err)
	}
}
