// NOTE: The following file is a modified version of the merkletree by Cameron Bergoon: https://github.com/cbergoon/merkletree
/*
MIT License

Copyright (c) 2017 Cameron Bergoon

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package rhine

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

//MerkleTree is the container for the tree. It holds a pointer to the root of the tree,
//a list of pointers to the Leaf nodes, and the merkle root.
type MerkleTree struct {
	Root               *Node
	MerkleRootInternal []byte
	Leafs              []*Node
}

//Node represents a node, root, or Leaf in the tree. It stores pointers to its immediate
//relationships, a hash, the content stored if it is a Leaf, and other metadata.
type Node struct {
	Parent *Node
	Left   *Node
	Right  *Node
	Leaf   bool
	Dup    bool
	Hash   []byte
	C      DSLeafContent
}

//verifyNode walks down the tree until hitting a Leaf, calculating the hash at each level
//and returning the resulting hash of Node n.
func (n *Node) verifyNode() ([]byte, error) {
	if n.Leaf {
		return n.C.CalculateHash()
	}
	rightBytes, err := n.Right.verifyNode()
	if err != nil {
		return nil, err
	}

	leftBytes, err := n.Left.verifyNode()
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	if _, err := h.Write(append(leftBytes, rightBytes...)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

//calculateNodeHash is a helper function that calculates the hash of the node.
func (n *Node) calculateNodeHash() ([]byte, error) {
	if n.Leaf {
		return n.C.CalculateHash()
	}

	h := sha256.New()
	if _, err := h.Write(append(n.Left.Hash, n.Right.Hash...)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

//NewTree creates a new Merkle Tree using the content cs.
func NewTree(cs []DSLeafContent) (*MerkleTree, error) {

	t := &MerkleTree{}
	root, leafs, err := buildWithContent(cs, t)
	if err != nil {
		return nil, err
	}
	t.Root = root
	t.Leafs = leafs
	t.MerkleRootInternal = root.Hash
	return t, nil
}

//NewTreeWithHashStrategy creates a new Merkle Tree using the content cs using the provided hash
//strategy. Note that the hash type used in the type that implements the Content interface must
//match the hash type profided to the tree.
func NewTreeWithHashStrategy(cs []DSLeafContent) (*MerkleTree, error) {
	t := &MerkleTree{}
	root, leafs, err := buildWithContent(cs, t)
	if err != nil {
		return nil, err
	}
	t.Root = root
	t.Leafs = leafs
	t.MerkleRootInternal = root.Hash
	return t, nil
}

// GetMerklePath: Get Merkle path and indexes(left Leaf or right Leaf)
func (m *MerkleTree) GetMerklePath(content DSLeafContent) ([][]byte, []int64, error) {
	for _, current := range m.Leafs {
		ok, err := current.C.Equals(content)
		if err != nil {
			return nil, nil, err
		}

		if ok {
			currentParent := current.Parent
			var merklePath [][]byte
			var index []int64
			for currentParent != nil {
				if bytes.Equal(currentParent.Left.Hash, current.Hash) {
					merklePath = append(merklePath, currentParent.Right.Hash)
					index = append(index, 1) // right Leaf
				} else {
					merklePath = append(merklePath, currentParent.Left.Hash)
					index = append(index, 0) // left Leaf
				}
				current = currentParent
				currentParent = currentParent.Parent
			}
			return merklePath, index, nil
		}
	}
	return nil, nil, nil
}

//buildWithContent is a helper function that for a given set of Contents, generates a
//corresponding tree and returns the root node, a list of Leaf nodes, and a possible error.
//Returns an error if cs contains no Contents.
func buildWithContent(cs []DSLeafContent, t *MerkleTree) (*Node, []*Node, error) {
	if len(cs) == 0 {
		return nil, nil, errors.New("error: cannot construct tree with no content")
	}
	var leafs []*Node
	for _, c := range cs {
		hash, err := c.CalculateHash()
		if err != nil {
			return nil, nil, err
		}

		leafs = append(leafs, &Node{
			Hash: hash,
			C:    c,
			Leaf: true,
		})
	}
	if len(leafs)%2 == 1 {
		duplicate := &Node{
			Hash: leafs[len(leafs)-1].Hash,
			C:    leafs[len(leafs)-1].C,
			Leaf: true,
			Dup:  true,
		}
		leafs = append(leafs, duplicate)
	}
	root, err := buildIntermediate(leafs, t)
	if err != nil {
		return nil, nil, err
	}

	return root, leafs, nil
}

//buildIntermediate is a helper function that for a given list of Leaf nodes, constructs
//the intermediate and root levels of the tree. Returns the resulting root node of the tree.
func buildIntermediate(nl []*Node, t *MerkleTree) (*Node, error) {
	var nodes []*Node
	for i := 0; i < len(nl); i += 2 {
		h := sha256.New()
		var left, right int = i, i + 1
		if i+1 == len(nl) {
			right = i
		}
		chash := append(nl[left].Hash, nl[right].Hash...)
		if _, err := h.Write(chash); err != nil {
			return nil, err
		}
		n := &Node{
			Left:  nl[left],
			Right: nl[right],
			Hash:  h.Sum(nil),
		}
		nodes = append(nodes, n)
		nl[left].Parent = n
		nl[right].Parent = n
		if len(nl) == 2 {
			return n, nil
		}
	}
	return buildIntermediate(nodes, t)
}

//MerkleRoot returns the unverified Merkle Root (hash of the root node) of the tree.
func (m *MerkleTree) MerkleRoot() []byte {
	return m.MerkleRootInternal
}

//RebuildTree is a helper function that will rebuild the tree reusing only the content that
//it holds in the leaves.
func (m *MerkleTree) RebuildTree() error {
	var cs []DSLeafContent
	for _, c := range m.Leafs {
		cs = append(cs, c.C)
	}
	root, leafs, err := buildWithContent(cs, m)
	if err != nil {
		return err
	}
	m.Root = root
	m.Leafs = leafs
	m.MerkleRootInternal = root.Hash
	return nil
}

//RebuildTreeWith replaces the content of the tree and does a complete rebuild; while the root of
//the tree will be replaced the MerkleTree completely survives this operation. Returns an error if the
//list of content cs contains no entries.
func (m *MerkleTree) RebuildTreeWith(cs []DSLeafContent) error {
	root, leafs, err := buildWithContent(cs, m)
	if err != nil {
		return err
	}
	m.Root = root
	m.Leafs = leafs
	m.MerkleRootInternal = root.Hash
	return nil
}

//VerifyTree verify tree validates the hashes at each level of the tree and returns true if the
//resulting hash at the root of the tree matches the resulting root hash; returns false otherwise.
func (m *MerkleTree) VerifyTree() (bool, error) {
	calculatedMerkleRoot, err := m.Root.verifyNode()
	if err != nil {
		return false, err
	}

	if bytes.Compare(m.MerkleRootInternal, calculatedMerkleRoot) == 0 {
		return true, nil
	}
	return false, nil
}

//VerifyContent indicates whether a given content is in the tree and the hashes are valid for that content.
//Returns true if the expected Merkle Root is equivalent to the Merkle root calculated on the critical path
//for a given content. Returns true if valid and false otherwise.
func (m *MerkleTree) VerifyContent(content DSLeafContent) (bool, error) {
	for _, l := range m.Leafs {
		ok, err := l.C.Equals(content)
		if err != nil {
			return false, err
		}

		if ok {
			currentParent := l.Parent
			for currentParent != nil {
				h := sha256.New()
				rightBytes, err := currentParent.Right.calculateNodeHash()
				if err != nil {
					return false, err
				}

				leftBytes, err := currentParent.Left.calculateNodeHash()
				if err != nil {
					return false, err
				}

				if _, err := h.Write(append(leftBytes, rightBytes...)); err != nil {
					return false, err
				}
				if bytes.Compare(h.Sum(nil), currentParent.Hash) != 0 {
					return false, nil
				}
				currentParent = currentParent.Parent
			}
			return true, nil
		}
	}
	return false, nil
}

//String returns a string representation of the node.
func (n *Node) String() string {
	return fmt.Sprintf("%t %t %v %s", n.Leaf, n.Dup, n.Hash, n.C)
}

//String returns a string representation of the tree. Only Leaf nodes are included
//in the output.
func (m *MerkleTree) String() string {
	s := ""
	for _, l := range m.Leafs {
		s += fmt.Sprint(l)
		s += "\n"
	}
	return s
}

func (m *MerkleTree) PrepareForMarshalling() {
	// We need to make the data structure noncyclical
	DeleteLinks(m.Root)

	// Clear leafs to save storage, they will need to gather anyway
	m.Leafs = nil
}

func (m *MerkleTree) RestoreAfterMarshalling() {

	// We need to restore the parent links that were deleted
	// Also restore the leafs properly
	m.Leafs = []*Node{}
	m.Leafs = RestoreLinks(m.Root, nil, m.Leafs)
}

func DeleteLinks(n *Node) {
	n.Parent = nil
	if n.Left != nil {
		DeleteLinks(n.Left)
	}
	if n.Right != nil {
		DeleteLinks(n.Right)
	}
}

func RestoreLinks(n *Node, par *Node, leafList []*Node) []*Node {
	n.Parent = par
	if n.Left != nil {
		leafList = RestoreLinks(n.Left, n, leafList)
	}
	if n.Leaf {
		leafList = append(leafList, n)
	}
	if n.Right != nil {
		leafList = RestoreLinks(n.Right, n, leafList)
	}
	return leafList
}

// Serialize a merkle tree using cbor
func (m *MerkleTree) Serialize() ([]byte, error) {
	res, err := cbor.Marshal(m)
	if err != nil {
		fmt.Println("Error: ", err)
		return res, err
	}
	return res, nil
}

// Serialize a merkle tree using cbor
func Deserialize(bytes []byte) (*MerkleTree, error) {
	res := &MerkleTree{}
	err := cbor.Unmarshal(bytes, res)
	if err != nil {
		fmt.Println("Error: ", err)
		return res, err
	}
	return res, nil
}
