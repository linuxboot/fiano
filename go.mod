module github.com/linuxboot/fiano

go 1.16

require (
	github.com/u-root/u-root v0.0.0-20210724144310-637617c480d4
	github.com/ulikunitz/xz v0.5.10
	golang.org/x/text v0.3.6
)

retract (
	v7.0.0
	v7.0.1
	v6.0.0
	v5.0.0
	v3.0.0
	v2.0.0
)
