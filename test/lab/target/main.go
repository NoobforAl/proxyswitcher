// Command target is a deliberately weak test site for the lab. It only ever runs
// on the lab's internal Docker network, and gives scanners something to find:
// reflected input, and a real SQL injection into an in-memory database that holds
// only the test rows below.
// It counts every request, so a run can prove nothing was sent twice.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type requestLog struct {
	mu     sync.Mutex
	counts map[string]int
	total  int
}

func (l *requestLog) add(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.counts[key]++
	l.total++
}

func (l *requestLog) summary() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	repeated := 0
	for _, count := range l.counts {
		if count > 1 {
			repeated++
		}
	}
	return fmt.Sprintf("total=%d unique=%d repeated=%d\n", l.total, len(l.counts), repeated)
}

func (l *requestLog) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.counts = make(map[string]int)
	l.total = 0
}

func main() {
	requests := &requestLog{counts: make(map[string]int)}
	db, err := openDatabase()
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/__log", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, requests.summary())
	})
	mux.HandleFunc("/__reset", func(w http.ResponseWriter, _ *http.Request) {
		requests.reset()
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><body><h1>Lab target</h1>
<a href="/about">about</a> <a href="/admin">admin</a> <a href="/backup">backup</a>
<a href="/search?q=hello">search</a> <a href="/item?id=1">item</a>
<form action="/search"><input name="q"><input type="submit"></form>
</body></html>`)
		case "/about", "/admin", "/backup", "/login", "/secret":
			fmt.Fprintf(w, "<html><body>page %s <a href=\"/\">home</a></body></html>", r.URL.Path)
		default:
			http.NotFound(w, r)
		}
	})
	// Reflected without escaping, on purpose.
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>results for %s</body></html>", r.URL.Query().Get("q"))
	})
	// Builds the query by string concatenation, on purpose.
	mux.HandleFunc("/item", func(w http.ResponseWriter, r *http.Request) {
		var title string
		err := db.QueryRowContext(r.Context(), "SELECT title FROM items WHERE id="+r.URL.Query().Get("id")).Scan(&title)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			fmt.Fprint(w, "<html><body>no such item</body></html>")
		case err != nil:
			http.Error(w, "SQL error: "+err.Error(), http.StatusInternalServerError)
		default:
			fmt.Fprintf(w, "<html><body>item: %s</body></html>", title)
		}
	})
	// Answers slowly, like a time-based test.
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		seconds, err := strconv.Atoi(r.URL.Query().Get("s"))
		if err != nil || seconds < 0 || seconds > 120 {
			seconds = 1
		}
		time.Sleep(time.Duration(seconds) * time.Second)
		fmt.Fprintln(w, "slow answer")
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/__") {
			requests.add(r.Method + " " + r.RequestURI)
		}
		mux.ServeHTTP(w, r)
	})

	certificate, err := selfSigned()
	if err != nil {
		log.Fatal(err)
	}
	secure := &http.Server{
		Addr: ":8443", Handler: handler, ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
	}
	go func() { log.Println(secure.ListenAndServeTLS("", "")) }()
	plain := &http.Server{Addr: ":8080", Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(plain.ListenAndServe())
}

func openDatabase() (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:lab?mode=memory&cache=shared")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.ExecContext(context.Background(), `CREATE TABLE items (id INTEGER PRIMARY KEY, title TEXT);
		INSERT INTO items VALUES (1, 'a long enough description of the first test item'), (2, 'the second test item');`)
	return db, err
}

func selfSigned() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "target"},
		DNSNames:     []string{"target"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
