//
// imageserver - Server for Ubuntu Touch system images
//
// Copyright (c) 2014 Canonical Ltd.
//
// Author: Jani Monoses <jani.monoses@canonical.com>

package main

// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License version 3, as published
// by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranties of
// MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
// PURPOSE.  See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program.  If not, see <http://www.gnu.org/licenses/>.

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"

	"code.google.com/p/go.crypto/openpgp"
	"github.com/remyoudompheng/go-liblzma"
)

const (
	secretKeyDir = "keys/gpg"
	wwwKeyDir    = "www/gpg"
)

type keyringJSON struct {
	Expiry int64  `json:"expiry,omitempty"`
	Type   string `json:"type"`
}

// Key describes a key used in signing image tarballs
type Key struct {
	typ     string
	dir     string
	name    string
	comment string
	email   string
	signer  string
	expiry  *time.Time
	entity  *openpgp.Entity
}

// signFile creates a GPG detached ASCII armored signature (.asc file) for a given file
// using the given key
func signFile(path string, ent *openpgp.Entity) {
	sigpath := path + ".asc"
	reader, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	writer, err := os.Create(sigpath)
	if err != nil {
		log.Fatal(err)
	}
	openpgp.ArmoredDetachSign(writer, ent, reader, nil)
}

// generate creates a GPG keypair and keyring tarballs
func (k *Key) generate() error {
	ent, err := openpgp.NewEntity(k.name, k.comment, k.email, nil)
	if err != nil {
		return err
	}

	//FIXME: how to not have subkeys otherwise?
	ent.Subkeys = nil

	k.entity = ent

	os.MkdirAll(k.dir, 0700)

	pubring, err := os.Create(filepath.Join(k.dir, "pubring.gpg"))
	if err != nil {
		return err
	}

	secring, err := os.Create(filepath.Join(k.dir, "secring.gpg"))
	if err != nil {
		return err
	}

	if err = ent.SerializePrivate(secring, nil); err != nil {
		return err
	}

	if err = ent.Serialize(pubring); err != nil {
		return err
	}
	k.writeKeyringJSON()
	return nil
}

func (k *Key) writeKeyringJSON() error {
	kr := &keyringJSON{Type: k.typ}
	if k.expiry != nil {
		kr.Expiry = k.expiry.Unix()
	}
	b, err := json.MarshalIndent(kr, "", "    ")
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath.Join(k.dir, "keyring.json"), b, 0600)
	if err != nil {
		return err
	}
	return err
}

// Default expiry date for image-signing and device-signing keys
var twoYearsFromNow = time.Now().AddDate(2, 0, 0)

var signingKeys = map[string]*Key{
	"archive-master": {
		name:   "[TESTING] Ubuntu Archive Master Signing Key",
		email:  "ftpmaster@ubuntu.com",
		expiry: nil,
		signer: "archive-master",
	},
	"image-master": {
		name:   "[TESTING] Ubuntu System Image Master Signing Key",
		email:  "system-image@ubuntu.com",
		expiry: nil,
		signer: "archive-master",
	},
	"image-signing": {
		name:    "[TESTING] Ubuntu System Image Signing Key",
		comment: "YYYY",
		email:   "system-image@ubuntu.com",
		expiry:  &twoYearsFromNow,
		signer:  "image-master",
	},
	"device-signing": {
		name:    "[TESTING] Random OEM Signing Key",
		comment: "YYYY",
		email:   "system-image@ubuntu.com",
		expiry:  &twoYearsFromNow,
		signer:  "image-signing",
	},
}

func createGPGKeys() error {
	for n, k := range signingKeys {
		log.Printf("Creating %s GPG key\n", n)
		k.typ = n
		k.dir = filepath.Join(secretKeyDir, n)
		err := k.generate()
		if err != nil {
			return err
		}
	}
	return nil
}

//tarDirectory makes a tar.xz archive from the given directory
func tarDirectory(dir, name string) error {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	defer tw.Close()

	if err := addFile(filepath.Join(dir, "keyring.json"), "keyring.json", tw); err != nil {
		return err
	}
	if err := addFile(filepath.Join(dir, "pubring.gpg"), "keyring.gpg", tw); err != nil {
		return err
	}

	tw.Close()
	tarxz, err := os.Create(name)
	if err != nil {
		return err
	}
	defer tarxz.Close()

	xzw, err := xz.NewWriter(tarxz, xz.LevelDefault)
	if err != nil {
		return err
	}
	defer xzw.Close()

	_, err = io.Copy(xzw, &buf)
	return nil
}

//addFile adds the file named name as a tar entry named tarname
func addFile(name string, tarname string, tw *tar.Writer) error {
	if tarname == "" {
		tarname = name
	}
	fi, err := os.Stat(name)
	if err != nil {
		return err
	}
	hdr, err := tar.FileInfoHeader(fi, "")
	if err != nil {
		return err
	}
	hdr.Name = tarname

	err = tw.WriteHeader(hdr)
	if err != nil {
		return err
	}

	f, err := os.Open(name)
	if err != nil {
		return err
	}

	_, err = io.Copy(tw, f)
	if err != nil {
		return err
	}
	tw.Flush()
	return nil
}

func createKeyrings() error {
	for d, k := range signingKeys {
		p := filepath.Join(wwwKeyDir, d) + ".tar.xz"
		log.Printf("Creating %s keyring tarball\n", d)
		if err := tarDirectory(k.dir, p); err != nil {
			return err
		}
		signFile(p, signingKeys[k.signer].entity)
	}
	return nil
}

func init() {
	os.MkdirAll(wwwKeyDir, 0700)
}

func generateKeys() {
	err := createGPGKeys()
	if err != nil {
		log.Fatal(err)
	}
	err = createKeyrings()
	if err != nil {
		log.Fatal(err)
	}
}
