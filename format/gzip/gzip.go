package gz

// https://tools.ietf.org/html/rfc1952
// TODO: test name, comment etc
// TODO: verify isize?

import (
	"compress/flate"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"

	"github.com/wader/fq/format"
	"github.com/wader/fq/format/registry"
	"github.com/wader/fq/pkg/decode"
)

var probeFormat decode.Group

func init() {
	registry.MustRegister(decode.Format{
		Name:        format.GZIP,
		Description: "gzip compression",
		Groups:      []string{format.PROBE},
		DecodeFn:    gzDecode,
		Dependencies: []decode.Dependency{
			{Names: []string{format.PROBE}, Group: &probeFormat},
		},
	})
}

const delfateMethod = 8

var compressionMethodNames = decode.UToStr{
	delfateMethod: "deflate",
}

var osNames = decode.UToStr{
	0:  "FAT filesystem (MS-DOS, OS/2, NT/Win32)",
	1:  "Amiga",
	2:  "VMS (or OpenVMS)",
	3:  "Unix",
	4:  "VM/CMS",
	5:  "Atari TOS",
	6:  "HPFS filesystem (OS/2, NT)",
	7:  "Macintosh",
	8:  "Z-System",
	9:  "CP/M",
	10: " TOPS-20",
	11: " NTFS filesystem (NT)",
	12: " QDOS",
	13: " Acorn RISCOS",
}

var deflateExtraFlagsNames = decode.UToStr{
	2: "slow",
	4: "fast",
}

func gzDecode(d *decode.D, in interface{}) interface{} {
	d.FieldRawLen("identification", 2*8, d.AssertBitBuf([]byte("\x1f\x8b")))
	compressionMethod := d.FieldU8("compression_method", d.MapUToStrSym(compressionMethodNames))
	hasHeaderCRC := false
	hasExtra := false
	hasName := false
	hasComment := false
	d.FieldStruct("flags", func(d *decode.D) {
		d.FieldBool("text")
		hasHeaderCRC = d.FieldBool("header_crc")
		hasExtra = d.FieldBool("extra")
		hasName = d.FieldBool("name")
		hasComment = d.FieldBool("comment")
		d.FieldU3("reserved")
	})
	d.FieldU32LE("mtime") // TODO: unix time
	switch compressionMethod {
	case delfateMethod:
		d.FieldU8("extra_flags", d.MapUToStrSym(deflateExtraFlagsNames))
	default:
		d.FieldU8("extra_flags")
	}
	d.FieldU8("os", d.MapUToStrSym(osNames))
	if hasExtra {
		// TODO:
		xLen := d.FieldU16("xlen")
		d.FieldRawLen("extra_fields", int64(xLen*8))
	}
	if hasName {
		d.FieldUTF8Null("name")
	}
	if hasComment {
		d.FieldUTF8Null("comment")
	}
	if hasHeaderCRC {
		// TODO: validate
		d.FieldRawLen("header_crc", 16, d.RawHex)
	}

	var rFn func(r io.Reader) io.Reader
	switch compressionMethod {
	case delfateMethod:
		// *bitio.Buffer implements io.ByteReader so hat deflate don't do own
		// buffering and might read more than needed messing up knowing compressed size
		rFn = func(r io.Reader) io.Reader { return flate.NewReader(r) }
	}

	readCompressedSize, uncompressedBB, dv, _, err := d.TryFieldReaderRangeFormat("uncompressed", d.Pos(), d.BitsLeft(), rFn, probeFormat, nil)
	if dv == nil && errors.As(err, &decode.FormatsError{}) {
		d.FieldRootBitBuf("uncompressed", uncompressedBB)
	}
	d.FieldRawLen("compressed", readCompressedSize)

	crc32W := crc32.NewIEEE()
	if _, err := io.Copy(crc32W, uncompressedBB.Copy()); err != nil {
		d.IOPanic(err)
	}
	d.FieldU32("crc32", d.ValidateU(uint64(binary.LittleEndian.Uint32(crc32W.Sum(nil)))), d.Hex)
	d.FieldU32LE("isize")

	return nil
}
