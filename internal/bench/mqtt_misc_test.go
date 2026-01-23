package bench

import (
	"bytes"
	"testing"
)

func TestMQTTWritePingResp(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := mqttWritePingResp(&buf); err != nil {
		t.Fatalf("mqttWritePingResp: %v", err)
	}
	if got := buf.Bytes(); !bytes.Equal(got, []byte{0xD0, 0x00}) {
		t.Fatalf("unexpected bytes: %v", got)
	}
}
