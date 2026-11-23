module github.com/junkerderprovinz/parleyport

go 1.26.10

toolchain go1.27.4

require (
	github.com/coder/websocket v1.8.15
	github.com/junkerderprovinz/parleyport/kit v1.1.0
	golang.org/x/crypto v0.59.0
)

require (
	golang.org/x/net v0.63.0 // indirect
	golang.org/x/text v0.44.0 // indirect
)

replace github.com/junkerderprovinz/parleyport/kit => ./kit
