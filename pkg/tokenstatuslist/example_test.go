package tokenstatuslist_test

import (
	"fmt"

	"github.com/SUNET/vc/pkg/tokenstatuslist"
)

func ExampleNew() {
	statuses := []uint8{
		tokenstatuslist.StatusValid,
		tokenstatuslist.StatusInvalid,
		tokenstatuslist.StatusSuspended,
		tokenstatuslist.StatusValid,
	}
	sl := tokenstatuslist.New(statuses)

	fmt.Println("length:", sl.Len())
	// Output:
	// length: 4
}

func ExampleNewWithConfig() {
	statuses := []uint8{
		tokenstatuslist.StatusValid,
		tokenstatuslist.StatusInvalid,
	}
	sl := tokenstatuslist.NewWithConfig(statuses, "https://issuer.example.com", "https://issuer.example.com/statuslist/1")

	fmt.Println("length:", sl.Len())
	fmt.Println("issuer:", sl.Issuer)
	fmt.Println("subject:", sl.Subject)
	// Output:
	// length: 2
	// issuer: https://issuer.example.com
	// subject: https://issuer.example.com/statuslist/1
}

func ExampleStatusList_Get() {
	statuses := []uint8{
		tokenstatuslist.StatusValid,
		tokenstatuslist.StatusInvalid,
		tokenstatuslist.StatusSuspended,
	}
	sl := tokenstatuslist.New(statuses)

	s0, _ := sl.Get(0)
	s1, _ := sl.Get(1)
	s2, _ := sl.Get(2)

	fmt.Println("index 0:", s0)
	fmt.Println("index 1:", s1)
	fmt.Println("index 2:", s2)
	// Output:
	// index 0: 0
	// index 1: 1
	// index 2: 2
}

func ExampleStatusList_Set() {
	statuses := []uint8{
		tokenstatuslist.StatusValid,
		tokenstatuslist.StatusValid,
	}
	sl := tokenstatuslist.New(statuses)

	before, _ := sl.Get(1)
	fmt.Println("before:", before)

	_ = sl.Set(1, tokenstatuslist.StatusSuspended)
	after, _ := sl.Get(1)
	fmt.Println("after:", after)
	// Output:
	// before: 0
	// after: 2
}

func ExampleStatusList_Len() {
	sl := tokenstatuslist.New([]uint8{0, 0, 0, 0, 0})
	fmt.Println("length:", sl.Len())
	// Output:
	// length: 5
}

func ExampleCompressAndEncode() {
	statuses := []uint8{
		tokenstatuslist.StatusValid,
		tokenstatuslist.StatusInvalid,
		tokenstatuslist.StatusSuspended,
	}

	encoded, err := tokenstatuslist.CompressAndEncode(statuses)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	// Decode and decompress to verify round-trip
	decoded, err := tokenstatuslist.DecodeAndDecompress(encoded)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("round-trip match:", decoded[0] == statuses[0] && decoded[1] == statuses[1] && decoded[2] == statuses[2])
	fmt.Println("decoded[0]:", decoded[0])
	fmt.Println("decoded[1]:", decoded[1])
	fmt.Println("decoded[2]:", decoded[2])
	// Output:
	// round-trip match: true
	// decoded[0]: 0
	// decoded[1]: 1
	// decoded[2]: 2
}

func ExampleDecodeAndDecompress() {
	// First encode some statuses
	original := []uint8{0, 1, 2, 0, 1}
	encoded, err := tokenstatuslist.CompressAndEncode(original)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	// Then decode and decompress
	statuses, err := tokenstatuslist.DecodeAndDecompress(encoded)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("length:", len(statuses))
	fmt.Println("statuses:", statuses)
	// Output:
	// length: 5
	// statuses: [0 1 2 0 1]
}

func ExampleGetStatus() {
	statuses := []uint8{0, 1, 2, 0}

	s, err := tokenstatuslist.GetStatus(statuses, 2)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("status at index 2:", s)
	// Output:
	// status at index 2: 2
}
