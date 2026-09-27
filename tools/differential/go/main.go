// A differential-testing peer over cloudflare/odoh-go.
//
// The driver in ../differential.ml starts this program and exchanges one JSON
// object per line with it: a request on standard input, its answer on standard
// output, strictly in turn. Every byte string is lowercase hexadecimal.
//
//	request:  {"op": "target", ...}
//	answer:   {"ok": true, ...}
//	          {"ok": false, "error": "..."}
//
// The operations are:
//
//	hello    which implementation this is
//	target   derive the target key from seed, decrypt query, and encrypt
//	         response to it: the peer as the target of an OCaml client
//	query    encrypt query for the first configuration of configs, and keep the
//	         context under handle: the peer as a client of an OCaml target
//	open     decrypt response with the context kept under handle
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/cisco/go-hpke"
	odoh "github.com/cloudflare/odoh-go"
)

const moduleVersion = "v1.0.1-0.20230926114050-f39fa019b017"

type request struct {
	Op              string `json:"op"`
	KEM             int    `json:"kem"`
	KDF             int    `json:"kdf"`
	AEAD            int    `json:"aead"`
	Seed            string `json:"seed"`
	Configs         string `json:"configs"`
	Query           string `json:"query"`
	Padding         int    `json:"padding"`
	Response        string `json:"response"`
	ResponsePadding int    `json:"response_padding"`
	Handle          int    `json:"handle"`
}

type answer map[string]any

var contexts = map[int]odoh.QueryContext{}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("invalid hex from the driver: %v", err))
	}
	return b
}

func target(r request) (answer, error) {
	kp, err := odoh.CreateKeyPairFromSeed(hpke.KEMID(r.KEM), hpke.KDFID(r.KDF),
		hpke.AEADID(r.AEAD), unhex(r.Seed))
	if err != nil {
		return nil, err
	}
	configs := odoh.CreateObliviousDoHConfigs([]odoh.ObliviousDoHConfig{kp.Config})
	message, err := odoh.UnmarshalDNSMessage(unhex(r.Query))
	if err != nil {
		return nil, err
	}
	query, rctx, err := kp.DecryptQuery(message)
	if err != nil {
		return nil, err
	}
	resp := odoh.CreateObliviousDNSResponse(unhex(r.Response), uint16(r.ResponsePadding))
	encrypted, err := rctx.EncryptResponse(resp)
	if err != nil {
		return nil, err
	}
	return answer{
		"configs":       hex.EncodeToString(configs.Marshal()),
		"key_id":        hex.EncodeToString(kp.Config.Contents.KeyID()),
		"query":         hex.EncodeToString(query.DnsMessage),
		"query_padding": len(query.Padding),
		"response":      hex.EncodeToString(encrypted.Marshal()),
	}, nil
}

func query(r request) (answer, error) {
	configs, err := odoh.UnmarshalObliviousDoHConfigs(unhex(r.Configs))
	if err != nil {
		return nil, err
	}
	if len(configs.Configs) == 0 {
		return nil, errors.New("no supported configuration")
	}
	contents := configs.Configs[0].Contents
	q := odoh.CreateObliviousDNSQuery(unhex(r.Query), uint16(r.Padding))
	message, ctx, err := contents.EncryptQuery(q)
	if err != nil {
		return nil, err
	}
	contexts[r.Handle] = ctx
	return answer{"query": hex.EncodeToString(message.Marshal())}, nil
}

func open(r request) (answer, error) {
	ctx, found := contexts[r.Handle]
	if !found {
		return nil, fmt.Errorf("no context %d", r.Handle)
	}
	delete(contexts, r.Handle)
	message, err := odoh.UnmarshalDNSMessage(unhex(r.Response))
	if err != nil {
		return nil, err
	}
	dns, err := ctx.OpenAnswer(message)
	if err != nil {
		return nil, err
	}
	return answer{"response": hex.EncodeToString(dns)}, nil
}

func handle(r request) (a answer, err error) {
	// odoh-go slices peer input without checking its length.
	defer func() {
		if p := recover(); p != nil {
			a, err = nil, fmt.Errorf("panic: %v", p)
		}
	}()
	switch r.Op {
	case "hello":
		return answer{"implementation": "github.com/cloudflare/odoh-go", "version": moduleVersion}, nil
	case "target":
		return target(r)
	case "query":
		return query(r)
	case "open":
		return open(r)
	}
	return nil, fmt.Errorf("unknown operation %q", r.Op)
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<24)
	out := json.NewEncoder(os.Stdout)
	for in.Scan() {
		var r request
		if err := json.Unmarshal(in.Bytes(), &r); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		a, err := handle(r)
		if err != nil {
			a = answer{"ok": false, "error": err.Error()}
		} else {
			a["ok"] = true
		}
		if err := out.Encode(a); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
}
