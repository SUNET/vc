package didcomm_test

import (
	"encoding/json"
	"fmt"

	"github.com/SUNET/vc/pkg/didcomm"
	"github.com/SUNET/vc/pkg/didcomm/message"
)

func ExampleMediaTypePlaintext() {
	fmt.Println(didcomm.MediaTypePlaintext)
	fmt.Println(didcomm.MediaTypeSigned)
	fmt.Println(didcomm.MediaTypeEncrypted)
	// Output:
	// application/didcomm-plain+json
	// application/didcomm-signed+json
	// application/didcomm-encrypted+json
}

func ExamplePackPlaintext() {
	msg := message.New(
		message.WithID("msg-001"),
		message.WithType(didcomm.MessageTypePing),
		message.WithFrom("did:example:alice"),
		message.WithTo("did:example:bob"),
		message.WithBody(map[string]any{"response_requested": true}),
	)

	result, err := didcomm.PackPlaintext(msg)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("media type:", result.MediaType)

	// Verify the packed message is valid JSON with expected fields
	var parsed map[string]any
	if err := json.Unmarshal(result.Message, &parsed); err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("id:", parsed["id"])
	fmt.Println("type:", parsed["type"])
	fmt.Println("from:", parsed["from"])
	// Output:
	// media type: application/didcomm-plain+json
	// id: msg-001
	// type: https://didcomm.org/trust-ping/2.0/ping
	// from: did:example:alice
}

func ExampleErrMissingID() {
	fmt.Println(didcomm.ErrMissingID)
	fmt.Println(didcomm.ErrMissingType)
	// Output:
	// didcomm: message missing id
	// didcomm: message missing type
}
