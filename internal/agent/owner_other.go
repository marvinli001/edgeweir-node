//go:build !unix

package agent

func chownToUser(string, ...string) error { return nil }

func letWorkersIn(string, ...string) error { return nil }
