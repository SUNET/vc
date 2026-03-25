package logger_test

import (
	"fmt"

	"github.com/SUNET/vc/pkg/logger"
)

func ExampleNewSimple() {
	log := logger.NewSimple("myservice")
	fmt.Printf("%T\n", log)
	// Output:
	// *logger.Log
}

func ExampleLog_New() {
	log := logger.NewSimple("myservice")
	sub := log.New("subsystem")
	fmt.Printf("%T\n", sub)
	// Output:
	// *logger.Log
}
