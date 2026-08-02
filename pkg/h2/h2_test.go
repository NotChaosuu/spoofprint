package h2

import "testing"

func pseudo(order ...string) []string { return order }

func TestAkamai_RealBrowserStrings(t *testing.T) {
	cases := []struct {
		name string
		f    Frames
		want string
	}{
		{
			"chrome",
			Frames{
				Settings:     []Setting{{1, 65536}, {2, 0}, {4, 6291456}, {6, 262144}},
				WindowUpdate: 15663105,
				PseudoOrder:  pseudo(":method", ":authority", ":scheme", ":path"),
			},
			"1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
		},
		{
			"firefox",
			Frames{
				Settings:     []Setting{{1, 65536}, {4, 131072}, {5, 16384}},
				WindowUpdate: 12517377,
				Priorities: []Priority{
					{3, false, 0, 201}, {5, false, 0, 101}, {7, false, 0, 1},
					{9, false, 7, 1}, {11, false, 3, 1}, {13, false, 0, 241},
				},
				PseudoOrder: pseudo(":method", ":path", ":authority", ":scheme"),
			},
			"1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
		},
		{
			"safari",
			Frames{
				Settings:     []Setting{{2, 0}, {4, 4194304}, {3, 100}},
				WindowUpdate: 10485760,
				PseudoOrder:  pseudo(":method", ":scheme", ":path", ":authority"),
			},
			"2:0;4:4194304;3:100|10485760|0|m,s,p,a",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Akamai(c.f); got != c.want {
				t.Errorf("Akamai(%s) =\n  %q\nwant\n  %q", c.name, got, c.want)
			}
		})
	}
}

func TestAkamai_NoWindowUpdate(t *testing.T) {
	f := Frames{Settings: []Setting{{1, 4096}}, PseudoOrder: pseudo(":method", ":path", ":scheme", ":authority")}

	if got := Akamai(f); got != "1:4096|0|0|m,p,s,a" {
		t.Errorf("got %q", got)
	}
}

func TestAkamai_SettingsOrderPreserved(t *testing.T) {
	f := Frames{Settings: []Setting{{6, 262144}, {1, 65536}}}
	if got := settingsPart(f.Settings); got != "6:262144;1:65536" {
		t.Errorf("settings order not preserved: %q", got)
	}
}
