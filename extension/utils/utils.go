package utils

func IsIPv4(address string) bool {
	return address != "" && address[0] != ':' && address[0] != '['
}
