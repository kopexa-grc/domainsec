GO_TEST = go tool gotest.tools/gotestsum --format pkgname

#   🧪 Testing     #
##@ Testing

test/ci: test/unit

test/unit:
	mkdir -p build/reports
	$(GO_TEST) --junitfile build/reports/test-unit.xml -- -race ./... -count=1 -short -cover -coverprofile build/reports/unit-test-coverage.out