module main

go 1.20

require github.com/salrashid123/golang-jwt-tink v0.0.0-00010101000000-000000000000

require (
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/tink-crypto/tink-go/v2 v2.1.0
)

require (
	golang.org/x/crypto v0.21.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)

replace github.com/salrashid123/golang-jwt-tink => ../
