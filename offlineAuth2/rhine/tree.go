package rhine

type SubZone struct {
	name string
	al   AuthorityLevel
}

type Leaf struct {
	zone SubZone
}
