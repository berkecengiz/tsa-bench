package tsp

// ParseResponseTolerantly exposes the tolerant parser to the external test
// package, which needs the mock responder to produce signed fixtures and so
// cannot live in package tsp (mock imports tsp).
var ParseResponseTolerantly = parseResponseTolerantly
