package oath

type ReaderPresence int

const (
	_                          = iota
	Available   ReaderPresence = iota
	Unavailable ReaderPresence = iota
)

type ReaderStatus interface {
	Availability() ReaderPresence
	Id() string
	Get() Reader
}

type ReaderDiscoverer interface {
	StatusChannel() (chan ReaderStatus, error)
}

type Reader interface {
	ReadCodeWithoutPassword() (string, error)
	ReadCodeWithPassword(password string) (string, error)
}
