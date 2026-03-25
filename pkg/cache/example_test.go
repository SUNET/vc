package cache_test

import (
	"context"
	"fmt"
	"time"

	"github.com/SUNET/vc/pkg/cache"
)

func ExampleNewMemoryCache() {
	c := cache.NewMemoryCache[string](5 * time.Minute)
	defer c.Stop()

	fmt.Printf("%T\n", c)
	// Output:
	// *cache.MemoryCache[string]
}

func ExampleMemoryCache_Set() {
	ctx := context.Background()
	c := cache.NewMemoryCache[string](5 * time.Minute)
	defer c.Stop()

	c.Set(ctx, "greeting", "hello")

	val, found := c.Get(ctx, "greeting")
	fmt.Println("found:", found)
	fmt.Println("value:", val)
	// Output:
	// found: true
	// value: hello
}

func ExampleMemoryCache_Get() {
	ctx := context.Background()
	c := cache.NewMemoryCache[int](5 * time.Minute)
	defer c.Stop()

	// Get a key that does not exist
	_, found := c.Get(ctx, "missing")
	fmt.Println("missing key found:", found)

	// Set and get a key
	c.Set(ctx, "count", 42)
	val, found := c.Get(ctx, "count")
	fmt.Println("count found:", found)
	fmt.Println("count value:", val)
	// Output:
	// missing key found: false
	// count found: true
	// count value: 42
}

func ExampleMemoryCache_Delete() {
	ctx := context.Background()
	c := cache.NewMemoryCache[string](5 * time.Minute)
	defer c.Stop()

	c.Set(ctx, "key", "value")
	fmt.Println("before delete:", c.Len())

	c.Delete(ctx, "key")
	_, found := c.Get(ctx, "key")
	fmt.Println("after delete found:", found)
	fmt.Println("after delete len:", c.Len())
	// Output:
	// before delete: 1
	// after delete found: false
	// after delete len: 0
}

func ExampleMemoryCache_Len() {
	ctx := context.Background()
	c := cache.NewMemoryCache[string](5 * time.Minute)
	defer c.Stop()

	fmt.Println("empty cache len:", c.Len())

	c.Set(ctx, "a", "alpha")
	c.Set(ctx, "b", "bravo")
	c.Set(ctx, "c", "charlie")
	fmt.Println("after 3 inserts len:", c.Len())
	// Output:
	// empty cache len: 0
	// after 3 inserts len: 3
}

func ExampleMemoryCache_SetWithTTL() {
	ctx := context.Background()
	c := cache.NewMemoryCache[string](5 * time.Minute)
	defer c.Stop()

	// Set a value with a custom TTL
	c.SetWithTTL(ctx, "session", "abc123", 30*time.Second)

	val, found := c.Get(ctx, "session")
	fmt.Println("found:", found)
	fmt.Println("value:", val)
	// Output:
	// found: true
	// value: abc123
}
