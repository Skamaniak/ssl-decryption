package session

import (
	"sync"
)

type Session struct {
	Address string
}

type Store struct {
	sessions map[int]chan Session
	mux      sync.Mutex
}

func NewSessionStore() *Store {
	return &Store{
		sessions: make(map[int]chan Session),
	}
}

func (ss *Store) ensureSessionChannel(key int) chan Session {
	ss.mux.Lock()
	defer ss.mux.Unlock()

	if ss.sessions[key] == nil {
		ss.sessions[key] = make(chan Session)
	}

	return ss.sessions[key]
}

func (ss *Store) PutSession(key int, session Session) {
	ss.ensureSessionChannel(key) <- session
}

func (ss *Store) GetSession(key int) chan Session {
	return ss.ensureSessionChannel(key)
}
