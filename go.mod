module github.com/gospider007/tools

go 1.21.3

require (
	github.com/andybalholm/brotli v1.0.6
	github.com/gospider007/kinds v0.0.0-20231024093643-7a4424f2d30e
	github.com/gospider007/re v0.0.0-20231015023348-717c984874af
	golang.org/x/image v0.13.0
	golang.org/x/net v0.17.0
	golang.org/x/text v0.13.0
)

replace (
	github.com/gospider007/re latest => github.com/tfyl/re latest
	github.com/gospider007/kinds latest => github.com/tfyl/kinds latest
)