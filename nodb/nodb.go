package nodb

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"
)

var (
	ErrInvalid = errors.New("entry name is invalid") // do not relly on this on Windows
	ErrNoExist = errors.New("entry does not exist")
)

type DB struct {
	path string
	locks *sync.Map // map[string]*sync.RWMutex
}

func Open(path string) (*DB, error) {
	db := &DB{
		path: filepath.Clean(path),
		locks: &sync.Map{},
	}

	dir, err := os.Open(db.path)
	if errors.Is(err, os.ErrNotExist) {
		err = os.MkdirAll(db.path, 0775)
		if err != nil {
			return nil, fmt.Errorf("nodb: failed to create database %s: %w", db.path, err)
		}

		dir, err = os.Open(db.path)
	}
	if err != nil {
		return nil, fmt.Errorf("nodb: failed to open database %s: %w", db.path, err)
	}
	defer dir.Close()

	entries, err := dir.Readdir(-1)
	if err != nil {
		return nil, fmt.Errorf("nodb: failed to stat database %s: %w", db.path, err)
	}

	for _, entry := range entries {
		name := entry.Name()

		if entry.IsDir() {
			return nil, fmt.Errorf("nodb: corrupted database %s: odd %s directory", db.path, name)
		}

		if name[len(name)-1] == 0xFF {
			if err := os.Remove(filepath.Join(db.path, name)); err != nil {
				return nil, fmt.Errorf("nodb: %s: could not remove temporary file %s: %w", db.path, name)
			}
			continue
		}

		if !utf8.ValidString(name) {
			return nil, fmt.Errorf("nodb: corrupted database %s: entry %s not utf8", db.path, name)
		}

		db.locks.Store(name, &sync.RWMutex{})
	}

	return db, nil
}

func (db DB) Delete(entry string) error {
	if !valid(entry) {
		return makeErrInvalid(entry)
	}

	mi, ok := db.locks.Load(entry)
	if !ok {
		return makeErrNoExist(entry)
	}
	m := mi.(*sync.RWMutex)

	m.Lock()
	defer m.Unlock()

	if err := os.Remove(filepath.Join(db.path, entry)); err != nil {
		return fmt.Errorf("nodb: %w", err)
	}

	if err := os.Remove(filepath.Join(db.path, entry+"\xFF")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("nodb: %w", err)
	}

	db.locks.Delete(entry)

	return nil
}

func (db DB) Get(entry string) ([]byte, error) {
	if !valid(entry) {
		return nil, makeErrInvalid(entry)
	}

	mi, ok := db.locks.Load(entry)
	if !ok {
		return nil, makeErrNoExist(entry)
	}
	m := mi.(*sync.RWMutex)

	m.RLock()
	defer m.RUnlock()

	b, err := ioutil.ReadFile(filepath.Join(db.path, entry))
	if err != nil {
		return b, fmt.Errorf("nodb: %w", err)
	}

	return b, nil
}

func (db DB) Put(entry string, b []byte) error {
	if !valid(entry) {
		return makeErrInvalid(entry)
	}

	mi, ok := db.locks.Load(entry)
	if !ok {
		mi = &sync.RWMutex{}
		db.locks.Store(entry, mi)
	}
	m := mi.(*sync.RWMutex)

	m.Lock()
	defer m.Unlock()

	if err := ioutil.WriteFile(filepath.Join(db.path, entry+"\xff"), b, 0664); err != nil {
		return fmt.Errorf("nodb: %w", err)
	}

	if err := os.Rename(filepath.Join(db.path, entry+"\xff"), filepath.Join(db.path, entry)); err != nil {
		return fmt.Errorf("nodb: %w", err)
	}

	return nil
}

func (db DB) List() []string {
	list := &[]string{}

	db.locks.Range(func (keyi, _ interface{}) bool {
		key := keyi.(string)
		*list = append(*list, key)

		return true
	})

	return *list
}

func valid(entry string) bool {
	switch {
	case !utf8.ValidString(entry): fallthrough
	case strings.Contains(entry, "/"): fallthrough
	case entry == ".": fallthrough
	case entry == "..":
		return false
	}

	return true
}

func makeErrInvalid(offender string) error {
	return fmt.Errorf("nodb: entry %s: %w", offender, ErrInvalid)
}

func makeErrNoExist(offender string) error {
	return fmt.Errorf("nodb: entry %s: %w", offender, ErrNoExist)
}
