// Copyright (c) 2013 Yoran Heling
// Modified from Go's /src/pkg/crypto/md4/md4_test.go

package tiger

import (
	"fmt"
	"io"
	"testing"
)

type tigerTest struct {
	out string
	in  string
}

var golden = []tigerTest{
	{"3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3", ""},
	{"77befbef2e7ef8ab2ec8f93bf587a7fc613e247f5f247809", "a"},
	{"c8ba0c91823f24eb1516c30d110c46474c0509a77c7275ef", "ab"},
	{"2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93", "abc"},
	{"bc701e56d8c3ee22a6b05e994b91dd8266db371bf6d3f4ba", "abcd"},
	{"bfd4041233531f1ef1e9a66d7a0cef76a3e0fe756b36a7d7", "abcde"},
	{"9895d378382b1e93a4a2f5ccd425453f01ddbab2137ce35e", "abcdef"},
	{"39cfb8a0a2683fac91c828dc52c586d23b73711f63e02726", "abcdefg"},
	{"6bdb656db7f8b062b448613becb1cf8f5c714a7c24960c4a", "abcdefgh"},
	{"7a17ca44438c5063b295b6712f47c342ee64012817200edb", "abcdefghi"},
	{"4a5c3a96c6eb137d9183c50c3afcdb698388e2815b679ac7", "abcdefghij"},
	{"fe454d2bf5cb8230e53546d1d18846031b1031e02a5a3ef0", "Discard medicine more than two years old."},
	{"97b9651bfa44743e5a0f0923828560a5c64a76bcf7c0d70c", "He who has a shady past knows that nice guys finish last."},
	{"156e051868d27253d38bf11b81df85888d0d694a2c24a090", "I wouldn't marry him with a ten foot pole."},
	{"bac87720f98c3a3aa799465156abe5d0d697fed0bbac0238", "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave"},
	{"9c7708f352ba1566bd0d77de5f68ab227c63c2ff9a439132", "The days of the digital watch are numbered.  -Tom Stoppard"},
	{"d079369510d74eaa5280343a25ba9804c9a5bded72b2c9ef", "Nepal premier won't resign."},
	{"681fd99188d794213da2102b67a74675e8466a07761a1022", "For every action there is an equal and opposite government program."},
	{"f83a8451e0bce81018301adbfd3d476cdd9502933b3ceb7e", "His money is twice tainted: 'taint yours and 'taint mine."},
	{"763fed32f0aa1a847c6a90cbcf564179ba0a109a87f4463b", "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977"},
	{"cc0ce3881d6fa02718773d14aa2dfb648a01d58e8be04e41", "It's a tiny change to the code and not completely disgusting. - Bob Manchek"},
	{"da051933c39a0d6c3df14ab2fe9e0a85200ade8cd8b76331", "size:  a.out:  bad magic"},
	{"2a751c89fe4972d8874c4822d16f95a735b6a629bcb3214a", "The major problem is with sendmail.  -Mark Horton"},
	{"6a0f397cb6c0bdc13ad0720550c37c98f8fd45f641cefa10", "Give me a rock, paper and scissors and I will move the world.  CCFestoon"},
	{"8ea630b7e4cd1f223c71f28a66de0be81082f7b3bca80fce", "If the enemy is within range, then so are you."},
	{"cf1a122f4dc7bf134614bbeb55c6e40f699c95b5435d4a21", "It's well we cannot hear the screams/That we create in others' dreams."},
	{"96565a214f51272ea9ca547b997c00ed07678fa016131130", "You remind me of a TV show, but that's all right: I watch it anyway."},
	{"7c3639c1452eb83963062be019b5b3d8ac34bdf2829c6d71", "C is as portable as Stonehedge!!"},
	{"5504029319409911a4758f12a79177791ed79c3cb3a0f60a", "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley"},
	{"f433743f5b22a685d7514b271f8823d0931d10c99b3ff476", "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule"},
	{"37fa782b57aaf7be1c4cd6214b747618804d5ca44b03b0be", "How can you write a big system without C++?  -Paul Glick"},
}

func TestGolden(t *testing.T) {
	for i := 0; i < len(golden); i++ {
		g := golden[i]
		c := New()
		for j := 0; j < 3; j++ {
			if j < 2 {
				io.WriteString(c, g.in)
			} else {
				io.WriteString(c, g.in[0:len(g.in)/2])
				c.Sum(nil)
				io.WriteString(c, g.in[len(g.in)/2:])
			}
			s := fmt.Sprintf("%x", c.Sum(nil))
			if s != g.out {
				t.Fatalf("tiger[%d](%s) = %s want %s", j, g.in, s, g.out)
			}
			c.Reset()
		}
	}
}

// Based on BenchmarkCrc32KB() of Go's /src/pkg/hash/crc32/crc32_test.go
func BenchmarkTigerKB(b *testing.B) {
	b.StopTimer()
	data := make([]uint8, 1024)
	for i := 0; i < 1024; i++ {
		data[i] = uint8(i)
	}
	c := New()
	b.StartTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		c.Write(data)
	}
}

// Since tiger is most often used within TTH, which only uses tiger on short
// (<=1024 bytes) messages, let's also test that.
func BenchmarkTigerSmall(b *testing.B) {
	b.StopTimer()
	data := make([]uint8, 512)
	for i := 0; i < 512; i++ {
		data[i] = uint8(i)
	}
	c := New()
	b.StartTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		c.Reset()
		c.Write(data)
		c.Sum(nil)
	}
}
