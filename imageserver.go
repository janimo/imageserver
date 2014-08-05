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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vaughan0/go-ini"

	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.exp/inotify"
)

const APP_VERSION = "0.1"

const (
	FULL_IMAGE    = "full"
	DELTA_IMAGE   = "delta"
	UBUNTU_SERVER = "http://system-image.ubuntu.com"
)

// IndexFile represents a per-device/per-channel index.json
type IndexFile struct {
	Global        map[string]string `json:"global"`
	Images        []Image           `json:"images"`
	path          string
	deviceTarball *TarballEntry
	customTarball *TarballEntry
}

// Image represents a given image within a channel
type Image struct {
	Base        int             `json:"base,omitempty"`
	Description string          `json:"description"`
	Files       []*TarballEntry `json:"files"`
	Type        string          `json:"type"`
	Version     int             `json:"version"`
}

// TarballEntry represents a tarball within an image
type TarballEntry struct {
	Checksum    string `json:"checksum"`
	Order       int    `json:"order"`
	Path        string `json:"path"`
	Signature   string `json:"signature"`
	Size        int64  `json:"size"`
	needsUpdate bool
	absPath     string
}

var (
	appRootPath string
	wwwPath     string
	poolPath    string
	gpgPath     string
	channelPath string
)

var (
	hostName    string
	httpPort    string
	httpsPort   string
	configFile  string
	genChannels bool
	genKeys     bool
)

func init() {
	cwd, _ := os.Getwd()
	flag.StringVar(&appRootPath, "root", cwd, "Server root directory containing keys and served content")
	flag.StringVar(&httpPort, "httpPort", "", "HTTP port. Overrides the value in the config file")
	flag.StringVar(&httpsPort, "httpsPort", "", "HTTPS port. Overrides the value in the config file")
	flag.StringVar(&configFile, "configFile", "config.ini", "Configuration file")
	flag.BoolVar(&genChannels, "genChannels", false, "Generate channels.json file from config.ini values")
	flag.BoolVar(&genKeys, "genKeys", false, "Generate GPG keys and keychains")
}

func initPaths() {
	wwwPath = filepath.Join(appRootPath, "www")
	poolPath = filepath.Join(wwwPath, "pool")
	os.MkdirAll(poolPath, 0755)
	gpgPath = filepath.Join(wwwPath, "gpg")
	channelPath = filepath.Join(wwwPath, "channels.json")
}

// exists returns true if a file exists at the given path
func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// NewTarballEntry creates a tarball of a given name
func NewTarballEntry(name string, order int) *TarballEntry {
	path := filepath.Join("/", "pool", name) + ".tar.xz"
	absPath := filepath.Join(wwwPath, path)
	log.Println("Looking for ", absPath)
	if !exists(absPath) {
		return nil
	}
	e := &TarballEntry{
		Path:        path,
		Order:       order,
		needsUpdate: true,
	}
	e.Signature = path + ".asc"
	e.absPath = absPath
	return e
}

// SetChecksum recalculates the SHA256 hash of the tarball
func (e *TarballEntry) SetChecksum() {
	b, err := ioutil.ReadFile(e.absPath)
	if err != nil {
		log.Fatal(err)
	}
	s := sha256.Sum256(b)
	e.Checksum = fmt.Sprintf("%x", s)
}

// SetSize updates the size field of the tarball
func (e *TarballEntry) SetSize() {
	fi, err := os.Lstat(e.absPath)
	if err != nil {
		log.Fatal(err)
	}
	e.Size = fi.Size()
}

// Update updates the tarball entry fields
func (e *TarballEntry) Update() {
	if e.needsUpdate {
		e.SetChecksum()
		e.SetSize()
		e.CreateSignature()
		e.needsUpdate = false
	}
}

// The private key used to sign the tarballs
var signingKey *openpgp.Entity

// createSignature creates a GPG detached ASCII armored signature file for the given file
func (e *TarballEntry) CreateSignature() {
	signFile(e.absPath, signingKey)
}

// currentTimestamp returns the current UTC timestamp
func currentTimestamp() string {
	return time.Now().UTC().Format(time.UnixDate)
}

// ubuntuIndices holds the data corresponding to all index.json files
var ubuntuIndices = make([]*IndexFile, 0)

func fileChanged(path string) {
	for _, index := range ubuntuIndices {
		if index.deviceTarball != nil && index.deviceTarball.absPath == path {
			index.deviceTarball.needsUpdate = true
			index.update()
		}
	}
	if channelPath == path {
		signFile(channelPath, signingKey)
		createIndices()
	}
}

func loadKeys() {
	keydir := os.Getenv("IMAGESERVER_GPGKEYDIR")
	if keydir == "" {
		keydir = filepath.Join(appRootPath, "keys", "gpg")
	}
	secring := filepath.Join(keydir, "image-signing", "secring.gpg")
	s, err := os.Open(secring)
	if err != nil {
		log.Printf("No secret keyring found in %s\n", keydir)
		log.Fatal("Run imageserver -genKeys")
	}
	defer s.Close()

	el, err := openpgp.ReadKeyRing(s)
	if err != nil {
		log.Fatal("Could not read secret keyring, will not sign tarballs:", err)
	}

	for _, e := range el {
		for i := range e.Identities {
			log.Printf("Signing key: \"%s\"\n", i)
			signingKey = e
			return
		}
	}
	if signingKey == nil {
		log.Fatal("Could not find a signing identity in the keyring")
	}
}

// authError is called when authentication fails and returns a HTTP error response
func authError(resp http.ResponseWriter, basicAuth *BasicAuth) {
	resp.Header().Set("WWW-Authenticate", `Basic: realm="`+basicAuth.realm+`"`)
	resp.WriteHeader(401)
	resp.Write([]byte("401 Unauthorized"))

}

// basicAuthHandler checks the  Authorization field in the request's HTTP header
// for a matching username and password. This is a primitive implementation of
// HTTP Basic Access Authentication, to be used only over TLS since the credentials are cleartext
func basicAuthHandler(basicAuth *BasicAuth, h http.Handler) http.Handler {
	f := func(resp http.ResponseWriter, req *http.Request) {
		if basicAuth != nil {
			auth := strings.SplitN(req.Header.Get("Authorization"), " ", 2)
			if len(auth) != 2 || auth[0] != "Basic" {
				authError(resp, basicAuth)
				return
			}
			b, err := base64.StdEncoding.DecodeString(auth[1])
			if err != nil {
				authError(resp, basicAuth)
				return
			}
			if string(b) != basicAuth.username+":"+basicAuth.password {
				authError(resp, basicAuth)
				return
			}
		}
		h.ServeHTTP(resp, req)
	}
	return http.HandlerFunc(f)
}

// startWebserver starts the HTTP and HTTPS servers
func startWebserver() {
	if httpPort == "" && httpsPort == "" {
		log.Println("No HTTP or HTTPS ports specified, not starting a web server")
		return
	}

	if !exists(gpgPath) {
		log.Fatal("No GPG keys found under www/gpg, try running go generate_keys.go")
	}
	http.Handle("/", basicAuthHandler(credentials, http.StripPrefix("/", http.FileServer(http.Dir(wwwPath)))))
	if httpPort != "" {
		log.Printf("Starting HTTP server on port %s\n", httpPort)
		go http.ListenAndServe(":"+httpPort, nil)
	}
	if httpsPort != "" {
		certdir := os.Getenv("IMAGESERVER_CERTDIR")
		if certdir == "" {
			certdir = filepath.Join(appRootPath, "keys", "ssl")
		}
		key := filepath.Join(certdir, "key.pem")
		cert := filepath.Join(certdir, "cert.pem")
		if !exists(key) || !exists(cert) {
			log.Printf("Missing TLS certificates in %s, not starting HTTPS server\n", certdir)
			log.Println("Try go run generate_cert.go")
			return
		}
		log.Printf("Starting HTTPS server on port %s, using TLS certificates in %s\n", httpsPort, certdir)
		go http.ListenAndServeTLS(":"+httpsPort, cert, key, nil)
	}
}

// getUbuntuIndex fetches the latest official index.json for the given channel and device
// FIXME - do not call multiple time for the same chan/dev combo
func getUbuntuIndex(channel, device string) (*IndexFile, error) {
	if !strings.HasPrefix(channel, "ubuntu-touch") {
		channel = "ubuntu-touch/" + channel
	}
	indexURL := fmt.Sprintf("%s/%s/%s/index.json", UBUNTU_SERVER, channel, device)
	log.Printf("Fetching %s\n", indexURL)
	resp, err := http.Get(indexURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	v := &IndexFile{}
	d := json.NewDecoder(resp.Body)
	err = d.Decode(&v)
	if err != nil {
		return nil, err
	}
	return v, nil
}

//fixupLinks changes relative links in the index file to point to the Ubuntu server URLs
func (index *IndexFile) fixupLinks() {
	for _, img := range index.Images {
		for _, f := range img.Files {
			f.Path = UBUNTU_SERVER + f.Path
			f.Signature = UBUNTU_SERVER + f.Signature
		}
	}
}

// update updates the index file when relevant files change
func (index *IndexFile) update() {
	index.deviceTarball.Update()
	if index.customTarball != nil {
		index.customTarball.Update()
	}
	index.Global["generated_at"] = currentTimestamp()

	if !strings.HasSuffix(filepath.Base(filepath.Dir(index.path)), "mako") {
		for _, img := range index.Images {
			if img.Type == FULL_IMAGE {
				// replace the device tarball entry
				img.Files[1] = index.deviceTarball
				// replace the custom tarball entry.
				// FIXME: assumption that 4 entries mean there's a custom tarball in there
				if index.customTarball != nil && len(img.Files) == 4 {
					img.Files[2] = index.customTarball
				}
			}
		}
	}
	index.save()
}

// save writes the index.json file to disk
func (index *IndexFile) save() {

	b, err := json.MarshalIndent(index, "", "    ")
	if err != nil {
		log.Fatal(err)
	}

	ioutil.WriteFile(index.path, b, 0644)
	signFile(index.path, signingKey)
	log.Printf("Wrote %s\n", index.path)
}

// Channels is the type of data represented by channels.json
type Channels map[string]Channel

// Device represents one device
type Device struct {
	Index string `json:"index"`
}

// Channel represents one channel
type Channel struct {
	Devices map[string]Device `json:"devices"`
}

// createIndices creates index.json files for all devices mentioned in channels.json
func createIndices() {
	f, err := os.Open(channelPath)
	if err != nil {
		log.Println("Could not open channels file")
		log.Fatal("Add devices and channels to config.ini then run imageserver -genChannels")
	}
	channels := Channels{}
	dec := json.NewDecoder(f)
	err = dec.Decode(&channels)
	if err != nil {
		log.Fatal(err)
	}

	for c, v := range channels {
		for d := range v.Devices {
			go createIndex(c, d)
		}
	}
}

// findTarball finds a tarball for a device/channel/pattern combination
// to be used as the device or custom tarball entry in the respective index.json
// The name can be device_mako_trusty-proposed.tar.xz, device_mako.tar.xz or just device.tar.xz
func findTarball(channel, device, pattern string) (tarball *TarballEntry) {
	//From most specific to most general name
	candidates := []string{
		pattern + "_" + device + "_" + channel,
		pattern + "_" + device,
		pattern,
	}
	for _, name := range candidates {
		tarball = NewTarballEntry(name, 1)
		if tarball != nil {
			log.Printf("Found %s tarball for %s %s\n", pattern, device, channel)
			break
		}
	}
	return
}

// createIndex fetches an Ubuntu index.json file and modifies for local use
func createIndex(channel, device string) {
	ubuntuIndex, err := getUbuntuIndex(channel, "mako")
	if err != nil {
		return
	}
	devicePath := filepath.Join(wwwPath, channel, device)
	os.MkdirAll(devicePath, 0755)
	ubuntuIndex.path = filepath.Join(devicePath, "index.json")
	ubuntuIndex.deviceTarball = findTarball(channel, device, "device")
	if ubuntuIndex.deviceTarball == nil {
		log.Fatalf("Did not find a device tarball for %s %s\n", device, channel)
	}
	ubuntuIndex.customTarball = findTarball(channel, device, "custom")
	ubuntuIndex.fixupLinks()
	ubuntuIndex.update()
	ubuntuIndices = append(ubuntuIndices, ubuntuIndex)
}

func ensureSignatures() {
	if exists(channelPath) {
		signFile(channelPath, signingKey)
	}
}

// BasicAuth is used to support HTTP Basic Access Authentication
type BasicAuth struct {
	realm    string
	username string
	password string
}

var credentials *BasicAuth

var config ini.File

// readConfig reads the options set in the config file
func readConfig(path string) {
	var err error
	if exists(path) {
		config, err = ini.LoadFile(path)
		if err != nil {
			log.Printf("Error loading config file: %s\n", err)
			return
		}
	}

	if config != nil {
		readAuthCredentials(config)
		readPorts(config)
		readHostname(config)
	}
}

// read hostname from the config file
func readHostname(f ini.File) {
	hostName, _ = f.Get("server", "hostname")
}

// readPorts reads the HTTP and HTTPS ports from the config file
// unless they are overriden by command line flags
func readPorts(f ini.File) {
	if httpPort == "" {
		httpPort, _ = f.Get("ports", "http")
	}
	if httpsPort == "" {
		httpsPort, _ = f.Get("ports", "https")
	}
}

// readAuthCredentials reads the optional HTTP Basic Auth credentials from the config file
func readAuthCredentials(f ini.File) {
	r, ok := f.Get("auth", "realm")
	if !ok {
		return
	}
	u, ok := f.Get("auth", "username")
	if !ok {
		return
	}
	p, ok := f.Get("auth", "password")
	if !ok {
		return
	}
	credentials = &BasicAuth{realm: r, username: u, password: p}
}

// setup does various initializations at program startup
func setup() {
	flag.Parse()
	initPaths()
	readConfig(configFile)
	if !genKeys {
		loadKeys()
		ensureSignatures()
	}
}

// periodically calls a given function at regular intervals
// Maybe time.Timer or time.Ticker are better for such a thing
func periodically(period time.Duration, f func()) {
	for {
		f()
		time.Sleep(period)
	}
}

func (ch Channels) add(channel, device string) {
	c, ok := ch[channel]
	if !ok {
		ch[channel] = Channel{Devices: map[string]Device{}}
		c = ch[channel]
	}
	c.Devices[device] = Device{Index: "/" + channel + "/" + device + "/index.json"}
}

func (ch *Channels) save() {
	b, err := json.MarshalIndent(ch, "", "     ")
	if err != nil {
		log.Fatal(err)
	}
	ioutil.WriteFile(channelPath, b, 0644)
	signFile(channelPath, signingKey)
	log.Printf("Created %s\n", channelPath)
}

// generateChannels creates a channels.json file from channel and device
// configuration from config.ini
func generateChannels() {
	if exists(channelPath) {
		log.Fatal("channels.json already exists, not overwriting it.")
	}
	ch := &Channels{}

	channels, _ := config.Get("channels", "channels")
	devices, _ := config.Get("channels", "devices")

	for _, c := range strings.Split(channels, ",") {
		for _, d := range strings.Split(devices, ",") {
			ch.add(c, d)
		}
	}

	ch.save()
}

func main() {
	fmt.Printf("Starting imageserver %s\n", APP_VERSION)
	setup()
	if genChannels {
		generateChannels()
		return
	}
	if genKeys {
		generateKeys()
		return
	}
	go periodically(10*time.Minute, createIndices)
	startWebserver()
	watcher, err := inotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}

	watcher.AddWatch(wwwPath, inotify.IN_CLOSE_WRITE|inotify.IN_MOVED_TO)
	watcher.AddWatch(poolPath, inotify.IN_CLOSE_WRITE|inotify.IN_MOVED_TO)
	for {
		select {
		case ev := <-watcher.Event:
			fileChanged(ev.Name)
		case err := <-watcher.Error:
			log.Println(err)
		}
	}
}
