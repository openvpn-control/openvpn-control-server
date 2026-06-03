package panel

// Result is the standard service response for panel HTTP handlers.
type Result struct {
	Status int
	Body   any
}
