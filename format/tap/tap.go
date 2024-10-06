package tap

// https://worldofspectrum.net/zx-modules/fileformats/tapformat.html

import (
	"bufio"
	"bytes"
	"embed"
	"fmt"

	"golang.org/x/text/encoding/charmap"

	"github.com/wader/fq/format"
	"github.com/wader/fq/pkg/bitio"
	"github.com/wader/fq/pkg/decode"
	"github.com/wader/fq/pkg/interp"
	"github.com/wader/fq/pkg/scalar"
)

//go:embed tap.md
var tapFS embed.FS

func init() {
	interp.RegisterFormat(
		format.TAP,
		&decode.Format{
			Description: "TAP tape format for ZX Spectrum computers",
			DecodeFn:    tapDecoder,
		})

	interp.RegisterFS(tapFS)
}

// The TAP- (and BLK-) format is nearly a direct copy of the data that is stored
// in real tapes, as it is written by the ROM save routine of the ZX-Spectrum.
// A TAP file is simply one data block or a group of 2 or more data blocks, one
// followed after the other. The TAP file may be empty.
func tapDecoder(d *decode.D) any {
	d.Endian = decode.LittleEndian

	var header headerMetadata

	d.FieldArray("blocks", func(d *decode.D) {
		for !d.End() {
			d.FieldStruct("block", func(d *decode.D) {
				// Length of the following data.
				length := d.FieldU16("length")

				// read header, fragment, or data block
				switch length {
				case 0:
					d.Fatalf("TAP fragments with 0 bytes are not supported")
				case 1:
					d.FieldStruct("data", func(d *decode.D) {
						d.FieldRawLen("bytes", 8)
					})
				case 19:
					d.FieldStruct("header", func(d *decode.D) {
						header = decodeHeader(d)
					})
				default:
					d.FieldStruct("data", func(d *decode.D) {
						decodeDataBlock(d, length, &header)
					})
				}

				// reset header data when block is not a header
				if length != 19 {
					header.reset()
				}
			})
		}
	})
	return nil
}

// decodes the different types of 19-byte header blocks.
func decodeHeader(d *decode.D) headerMetadata {
	blockHeader := headerMetadata{}

	blockStartPosition := d.Pos()

	// flag indicating the type of header block, usually 0 (standard speed data)
	d.FieldU8("flag", scalar.UintFn(func(s scalar.Uint) (scalar.Uint, error) {
		if s.Actual == 0x00 {
			s.Sym = "standard_speed_data"
		} else {
			s.Sym = "custom_data_block"
		}
		return s, nil
	}))

	// Header type
	dataType := d.FieldU8("data_type", scalar.UintFn(func(s scalar.Uint) (scalar.Uint, error) {
		switch s.Actual {
		case 0x00:
			s.Sym = "program"
		case 0x01:
			s.Sym = "numeric"
		case 0x02:
			s.Sym = "alphanumeric"
		case 0x03:
			s.Sym = "data"
		default:
			// unofficial header types
			s.Sym = fmt.Sprintf("unknown%02X", s.Actual)
		}
		return s, nil
	}))
	blockHeader.Type = int(dataType)

	// Loading name of the program. Filled with spaces (0x20) to 10 characters.
	d.FieldStr("program_name", 10, charmap.ISO8859_1)

	switch dataType {
	case 0x00:
		// Length of data following the header = length of BASIC program + variables.
		d.FieldU16("data_length")
		// LINE parameter of SAVE command. Value 32768 means "no auto-loading".
		// 0..9999 are valid line numbers.
		d.FieldU16("auto_start_line")
		// Variables area offset, relative to the start of the BASIC program.
		blockHeader.ProgramVariablesOffset = int(d.FieldU16("variables_offset"))
		blockHeader.IsBasicProgram = true
	case 0x01:
		// Length of data following the header = length of number array * 5 + 3.
		d.FieldU16("data_length")
		// Unused byte.
		d.FieldU8("unused0")
		// (1..26 meaning A..Z) + 128.
		d.FieldU8("variable_name", scalar.UintHex)
		// UnusedWord: 32768.
		d.FieldU16("unused1")
	case 0x02:
		// Length of data following the header = length of string array + 3.
		d.FieldU16("data_length")
		// Unused byte.
		d.FieldU8("unused0")
		// (1..26 meaning A$..Z$) + 192.
		d.FieldU8("variable_name", scalar.UintHex)
		// UnusedWord: 32768.
		d.FieldU16("unused1")
	case 0x03:
		// Length of data following the header, in case of a SCREEN$ header = 6912.
		d.FieldU16("data_length")
		// In case of a SCREEN$ header = 16384.
		d.FieldU16("start_address", scalar.UintHex)
		//	UnusedWord: 32768.
		d.FieldU16("unused")
	default:
		// Unofficial header types
		d.FieldU16("data_length")
		d.FieldU16("unknown1", scalar.UintHex)
		d.FieldU16("unknown2", scalar.UintHex)
	}

	// Simply all bytes XORed (including flag byte).
	d.FieldU8("checksum", d.UintValidate(calculateChecksum(d, blockStartPosition, d.Pos()-blockStartPosition)), scalar.UintHex)

	return blockHeader
}

func decodeDataBlock(d *decode.D, length uint64, blockHeader *headerMetadata) {
	blockStartPosition := d.Pos()

	// flag indicating the type of data block, usually 255 (standard speed data)
	d.FieldU8("flag", scalar.UintFn(func(s scalar.Uint) (scalar.Uint, error) {
		if s.Actual == 0xFF {
			s.Sym = "standard_speed_data"
		} else {
			s.Sym = "custom_data_block"
		}
		return s, nil
	}))

	// The essential data: length minus the flag/checksum bytes (may be empty)
	if blockHeader.IsBasicProgram {
		// when the last header type was "program", parse it as a BASIC program
		d.FieldStruct("program", func(d *decode.D) {
			d.FramedFn(int64(blockHeader.ProgramVariablesOffset*8), func(d *decode.D) {
				d.FieldArray("listing", func(d *decode.D) {
					for !d.End() {
						d.FieldStruct("line", func(d *decode.D) {
							d.Endian = decode.BigEndian
							d.FieldU16("line_number")
							d.Endian = decode.LittleEndian

							lineLength := d.FieldU16("byte_length")

							d.FieldStrFn("code", func(d *decode.D) string {
								data := d.BytesLen(int(lineLength))
								return decodeBasic(data)
							})
						})
					}
				})
			})
			d.FieldRawLen("variables", int64(int(length)-2-blockHeader.ProgramVariablesOffset)*8)
		})
	} else {
		d.FieldRawLen("bytes", int64(int(length)-2)*8)
	}

	// Simply all bytes (including flag byte) XORed
	d.FieldU8("checksum", d.UintValidate(calculateChecksum(d, blockStartPosition, d.Pos()-blockStartPosition)), scalar.UintHex)
}

func calculateChecksum(d *decode.D, blockStartPos, blockEndPos int64) uint64 {
	var blockSlice bytes.Buffer
	writer := bufio.NewWriter(&blockSlice)
	d.Copy(writer, bitio.NewIOReader(d.BitBufRange(blockStartPos, blockEndPos)))

	var checksum uint8
	for _, v := range blockSlice.Bytes() {
		checksum ^= v
	}
	return uint64(checksum)
}

type headerMetadata struct {
	Type                   int
	IsBasicProgram         bool
	ProgramVariablesOffset int
}

func (meta *headerMetadata) reset() {
	meta.Type = -1
	meta.IsBasicProgram = false
	meta.ProgramVariablesOffset = 0
}
