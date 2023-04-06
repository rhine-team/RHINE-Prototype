package rhine

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/upstream"
	"github.com/coredns/coredns/plugin/transfer"
)

func init() { plugin.Register("rhine", setup) }

func setup(c *caddy.Controller) error {
	zones, scionEnabled, err := fileParse(c)
	if err != nil {
		return plugin.Error("file", err)
	}

	f := Rhine{Zones: zones, scion: scionEnabled}
	// get the transfer plugin, so we can send notifies and send notifies on startup as well.
	c.OnStartup(func() error {
		t := dnsserver.GetConfig(c).Handler("transfer")
		if t == nil {
			return nil
		}
		f.transfer = t.(*transfer.Transfer) // if found this must be OK.
		go func() {
			for _, n := range zones.Names {
				f.transfer.Notify(n)
			}
		}()
		return nil
	})

	c.OnRestartFailed(func() error {
		t := dnsserver.GetConfig(c).Handler("transfer")
		if t == nil {
			return nil
		}
		go func() {
			for _, n := range zones.Names {
				f.transfer.Notify(n)
			}
		}()
		return nil
	})

	for _, n := range zones.Names {
		z := zones.Z[n]
		c.OnShutdown(z.OnShutdown)
		c.OnStartup(func() error {
			z.StartupOnce.Do(func() { z.Reload(f.transfer) })
			return nil
		})
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		f.Next = next
		return f
	})

	return nil
}

func fileParse(c *caddy.Controller) (Zones, bool, error) {
	z := make(map[string]*Zone)
	scion := false
	names := []string{}

	config := dnsserver.GetConfig(c)

	var openErr error
	reload := 1 * time.Minute

	for c.Next() {
		// file db.file [zones...]
		if !c.NextArg() {
			return Zones{}, false, c.ArgErr()
		}
		fileName := c.Val()

		origins := plugin.OriginsFromArgsOrServerBlock(c.RemainingArgs(), c.ServerBlockKeys)
		if !filepath.IsAbs(fileName) && config.Root != "" {
			fileName = filepath.Join(config.Root, fileName)
		}

		reader, err := os.Open(filepath.Clean(fileName))
		if err != nil {
			openErr = err
		}

		for i := range origins {
			z[origins[i]] = NewZone(origins[i], fileName)
			if openErr == nil {
				reader.Seek(0, 0)
				zone, err := Parse(reader, origins[i], fileName, 0)
				if err != nil {
					return Zones{}, false, err
				}
				z[origins[i]] = zone
			}
			names = append(names, origins[i])
		}

		for c.NextBlock() {
			switch c.Val() {
			case "reload":
				if !c.NextArg() {
					return Zones{}, false, errors.New("reload duration value is expected")
				}
				t := c.Val()
				d, err := time.ParseDuration(t)
				if err != nil {
					return Zones{}, false, plugin.Error("file", err)
				}
				reload = d
			case "scion":
				t := c.RemainingArgs()
				if len(t) < 1 {
					return Zones{}, false, errors.New("scion option value is expected")
				}
				if t[0] == "on" {
					scion = true
				} else if t[0] == "off" {
					scion = false
				} else {
					return Zones{}, false, c.Errf("unknown scion option: '%s'", t[0])
				}
			case "upstream":
				// remove soon
			default:
				return Zones{}, false, c.Errf("unknown property '%s'", c.Val())
			}
		}

		for i := range origins {
			z[origins[i]].ReloadInterval = reload
			z[origins[i]].Upstream = upstream.New()
		}
	}

	if openErr != nil {
		if reload == 0 {
			// reload hasn't been set make this a fatal error
			return Zones{}, false, plugin.Error("file", openErr)
		}
		log.Warningf("Failed to open %q: trying again in %s", openErr, reload)

	}
	return Zones{Z: z, Names: names}, scion, nil
}
