package rhine

import "strings"

func GetParentZone(subzone string) string {
	split := strings.SplitN(subzone, ".", 2)
	if len(split) > 1 {
		return split[1]
	} else {
		return ""
	}

}
