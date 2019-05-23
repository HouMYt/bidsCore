package bids_core

import (
	"encoding/binary"
	"github.com/btcsuite/fastsha256"
	"io"
)
const AggSiglength = 32
const RootSiglength = 32
type AggSig [AggSiglength]byte
type RootSig [RootSiglength]byte

// DoubleSha256 calculates sha256(sha256(b)) and returns the resulting bytes.
func DoubleSha256(b []byte) []byte {
	first := fastsha256.Sum256(b)
	second := fastsha256.Sum256(first[:])
	return second[:]
}

// DoubleSha256SH calculates sha256(sha256(b)) and returns the resulting bytes
// as a ShaHash.
func DoubleSha256SH(b []byte) ShaHash {
	first := fastsha256.Sum256(b)
	return ShaHash(fastsha256.Sum256(first[:]))
}
func writeElements(w io.Writer, elements ...interface{}) error {
	for _, element := range elements {
		err := writeElement(w, element)
		if err != nil {
			return err
		}
	}
	return nil
}
func writeElement(w io.Writer, element interface{}) error {
	var scratch [8]byte

	// Attempt to write the element based on the concrete type via fast
	// type assertions first.
	switch e := element.(type) {
	case int32:
		b := scratch[0:4]
		binary.LittleEndian.PutUint32(b, uint32(e))
		_, err := w.Write(b)
		if err != nil {
			return err
		}
		return nil

	case uint32:
		b := scratch[0:4]
		binary.LittleEndian.PutUint32(b, e)
		_, err := w.Write(b)
		if err != nil {
			return err
		}
		return nil

	case int64:
		b := scratch[0:8]
		binary.LittleEndian.PutUint64(b, uint64(e))
		_, err := w.Write(b)
		if err != nil {
			return err
		}
		return nil

	case uint64:
		b := scratch[0:8]
		binary.LittleEndian.PutUint64(b, e)
		_, err := w.Write(b)
		if err != nil {
			return err
		}
		return nil

	case bool:
		b := scratch[0:1]
		if e == true {
			b[0] = 0x01
		} else {
			b[0] = 0x00
		}
		_, err := w.Write(b)
		if err != nil {
			return err
		}
		return nil

	// Message header checksum.
	case [4]byte:
		_, err := w.Write(e[:])
		if err != nil {
			return err
		}
		return nil

	// IP address.
	case [16]byte:
		_, err := w.Write(e[:])
		if err != nil {
			return err
		}
		return nil

	case ShaHash:
		_, err := w.Write(e[:])
		if err != nil {
			return err
		}
		return nil
	case RootSig:
		_, err := w.Write(e[:])
		if err != nil {
			return err
		}
		return nil
	case AggSig:
		_, err := w.Write(e[:])
		if err != nil {
			return err
		}
		return nil
	}

	// Fall back to the slower binary.Write if a fast path was not available
	// above.
	return binary.Write(w, binary.LittleEndian, element)
}
func readElements(r io.Reader, elements ...interface{}) error {
	for _, element := range elements {
		err := readElement(r, element)
		if err != nil {
			return err
		}
	}
	return nil
}
// readElement reads the next sequence of bytes from r using little endian
// depending on the concrete type of element pointed to.
func readElement(r io.Reader, element interface{}) error {
	var scratch [8]byte

	// Attempt to read the element based on the concrete type via fast
	// type assertions first.
	switch e := element.(type) {
	case *int32:
		b := scratch[0:4]
		_, err := io.ReadFull(r, b)
		if err != nil {
			return err
		}
		*e = int32(binary.LittleEndian.Uint32(b))
		return nil

	case *uint32:
		b := scratch[0:4]
		_, err := io.ReadFull(r, b)
		if err != nil {
			return err
		}
		*e = binary.LittleEndian.Uint32(b)
		return nil

	case *int64:
		b := scratch[0:8]
		_, err := io.ReadFull(r, b)
		if err != nil {
			return err
		}
		*e = int64(binary.LittleEndian.Uint64(b))
		return nil

	case *uint64:
		b := scratch[0:8]
		_, err := io.ReadFull(r, b)
		if err != nil {
			return err
		}
		*e = binary.LittleEndian.Uint64(b)
		return nil

	case *bool:
		b := scratch[0:1]
		_, err := io.ReadFull(r, b)
		if err != nil {
			return err
		}
		if b[0] == 0x00 {
			*e = false
		} else {
			*e = true
		}
		return nil

	// Message header checksum.
	case *[4]byte:
		_, err := io.ReadFull(r, e[:])
		if err != nil {
			return err
		}
		return nil

	// IP address.
	case *[16]byte:
		_, err := io.ReadFull(r, e[:])
		if err != nil {
			return err
		}
		return nil

	case *ShaHash:
		_, err := io.ReadFull(r, e[:])
		if err != nil {
			return err
		}
		return nil
	case *AggSig:
		_, err := io.ReadFull(r,e[:])
		if err != nil {
			return err
		}
		return nil
	case *RootSig:
		_, err := io.ReadFull(r,e[:])
		if err != nil {
			return err
		}
		return nil
	}
	// Fall back to the slower binary.Read if a fast path was not available
	// above.
	return binary.Read(r, binary.LittleEndian, element)
}
