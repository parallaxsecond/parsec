package client

import (
	"io"
	"sync"
)

type conn struct {
	sync.Mutex
	rwc  *io.ReadWriteCloser
	path string
}

func (conn *conn) close() error {
	conn.Lock()
	defer conn.Unlock()
	if conn.rwc != nil {
		rwc := *conn.rwc
		rwc.Close()
	}
	conn.rwc = nil
	return nil
}

func (conn *conn) open() error {
	conn.Lock()
	defer conn.Unlock()
	// rwc, err := OpenParsec(conn.path)
	// if err != nil {
	// 	return err
	// }
	// conn.rwc = &rwc
	return nil
}
