package cbfs

import "os"

func Open(n string) (*Image, error) {
	f, err := os.Open(n)
	if err != nil {
		return nil, err
	}

	return NewImage(f)
}
