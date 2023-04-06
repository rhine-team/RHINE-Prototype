# Coredns + Rhine plugin

## Name

*rhine* - enables serving zone data from an RFC 1035-style master file with rhine & scion support.

## Description

The *rhine* plugin is used for an "old-style" DNS server. It serves from a preloaded file that exists
on disk contained RFC 1035 styled data. If the zone file contains signatures, correct RHINE answers(answer + ZSK + signatures + RCert)
are returned. It also supports scion, with scion enabled, scion TXT record will be returned in glue records.
If you use this setup you are responsible for re-signing the zonefile.

## Syntax

~~~
rhine DBFILE [ZONES...]
~~~

* **DBFILE** the database file to read and parse. If the path is relative, the path from the *root*
  plugin will be prepended to it.
* **ZONES** zones it should be authoritative for. If empty, the zones from the configuration block
  are used.

If you want to round-robin A and AAAA responses look at the *loadbalance* plugin.

~~~
rhine DBFILE [ZONES... ] {
    reload DURATION
    scion on/off
}
~~~

* `reload` interval to perform a reload of the zone if the SOA version changes. Default is one minute.
  Value of `0` means to not scan for changes and reload. For example, `30s` checks the zonefile every 30 seconds
  and reloads the zone when serial changes.

* `scion` option to enable/disable SCION support. 
  if enabled, SCION TXT record that contains SCION address will be returned in glue records instead of A and AAAA records.
## Examples

Load the `example.org` zone from `db.example.org` and enable scion support

~~~ corefile
example.org {
    rhine db.example.org {
        scion on
    }
}
~~~


Note that if you have a configuration like the following you may run into a problem of the origin
not being correctly recognized:

~~~ corefile
. {
    rhine db.example.org
}
~~~

We omit the origin for the file `db.example.org`, so this references the zone in the server block,
which, in this case, is the root zone. Any contents of `db.example.org` will then read with that
origin set; this may or may not do what you want.
It's better to be explicit here and specify the correct origin. This can be done in two ways:

~~~ corefile
. {
    rhine db.example.org example.org
}
~~~

Or

~~~ corefile
example.org {
    file db.example.org
}
~~~
