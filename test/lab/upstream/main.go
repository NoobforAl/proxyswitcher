// Command upstream is a minimal HTTP forward proxy, standing in for a real
// upstream proxy in the lab. It relays bytes without normalizing them, and
// refuses every host except the lab's target, so nothing it carries can reach a
// real site.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"io"
	"log"
	"net"
	"strings"
)

func main() {
	listen := flag.String("listen", ":3128", "address to listen on")
	allowed := flag.String("allow", "target", "the only host this proxy will connect to")
	flag.Parse()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handle(conn, *allowed)
	}
}

func handle(client net.Conn, allowed string) {
	defer client.Close()
	br := bufio.NewReader(client)
	var head bytes.Buffer
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return
		}
		head.Write(line)
		if len(bytes.TrimRight(line, "\r\n")) == 0 {
			break
		}
	}
	first, rest, _ := bytes.Cut(head.Bytes(), []byte("\n"))
	fields := strings.Fields(string(first))
	if len(fields) != 3 {
		io.WriteString(client, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
		return
	}
	method, target, version := fields[0], fields[1], fields[2]

	var addr, path string
	if method == "CONNECT" {
		addr = target
	} else {
		after, ok := strings.CutPrefix(target, "http://")
		if !ok {
			io.WriteString(client, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
			return
		}
		addr, path = after, "/"
		if i := strings.IndexAny(after, "/?"); i >= 0 {
			addr, path = after[:i], after[i:]
			if path[0] != '/' {
				path = "/" + path
			}
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(addr, "80")
		}
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host != allowed {
		log.Printf("refused %q: this lab proxy only reaches %q", addr, allowed)
		io.WriteString(client, "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
		return
	}
	server, err := net.Dial("tcp", addr)
	if err != nil {
		io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
		return
	}
	defer server.Close()
	log.Printf("relay %s %s", method, addr)

	if method == "CONNECT" {
		io.WriteString(client, "HTTP/1.1 200 OK\r\n\r\n")
	} else {
		io.WriteString(server, method+" "+path+" "+version+"\r\n")
		server.Write(rest)
	}
	go func() {
		io.Copy(server, br)
		if tcp, ok := server.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
	}()
	io.Copy(client, server)
}
