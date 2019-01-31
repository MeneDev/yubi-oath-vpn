package yubikey

import (
	"context"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestYubiReaderDiscovererNew(t *testing.T) {

}

func TestYubiReaderDiscoverer_StatusChannel(t *testing.T) {

	t.Run("calling once returns chanel", func(t *testing.T) {
		ctx := context.Background()
		discoverer, _ := YubiReaderDiscovererNew(ctx)
		ch, e := discoverer.StatusChannel()

		assert.NotNil(t, ch)
		assert.Nil(t, e)
	})

	t.Run("calling multiple times fails", func(t *testing.T) {
		ctx := context.Background()
		discoverer, _ := YubiReaderDiscovererNew(ctx)
		discoverer.StatusChannel()
		_, e := discoverer.StatusChannel()

		assert.Error(t, e)
	})
}
