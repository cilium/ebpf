package main

import (
	"bytes"
	"encoding/binary"
	"github.com/DataDog/ebpf"
	"io"
	"os"
	"unsafe"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// ByteOrder - host byte order
var ByteOrder binary.ByteOrder

func init() {
	ByteOrder = getHostByteOrder()
}

// getHostByteOrder - Returns the host byte order
func getHostByteOrder() binary.ByteOrder {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}

// recoverAsset - Recover ebpf asset
func recoverAsset(asset string) io.ReaderAt {
	buf, err := Asset(asset)
	if err != nil {
		logrus.Fatal(errors.Wrap(err, "couldn't find asset"))
	}
	return bytes.NewReader(buf)
}

// trigger - Creates and then removes a tmp folder to trigger the probes
func trigger() error {
	logrus.Println("Generating events to trigger the probes ...")

	// Creating a tmp directory to trigger the probes
	tmpDir := "/tmp/test_folder"
	logrus.Printf("creating %v", tmpDir)
	err := os.MkdirAll(tmpDir, 0666)
	if err != nil {
		return err
	}

	// Removing the tmp directory
	return os.RemoveAll(tmpDir)
}

// dumpSharedMap - Dumps the content of the provided map at the provided key
func dumpSharedMap(sharedMap *ebpf.Map) error {
	var key, val uint32
	entries := sharedMap.Iterate()
	for entries.Next(&key, &val) {
		// Order of keys is non-deterministic due to randomized map seed
		logrus.Printf("%v contains %v at key %v", sharedMap, val, key)
	}
	return entries.Err()
}
