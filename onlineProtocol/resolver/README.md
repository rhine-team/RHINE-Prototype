# Recursive resolver with rhine support

This is a recursive resolver developed based on sdns, which supports rhine verification.

## Rhine Verfication

The resolver will verify the RoA(realm of authority) of zone and the signatures of data in the response after it successfully gets it from authoritative nameservers.

The RoA of a zone contains RCert, DSP, ZSK, and the signature of ZSK.
1. Parse RCert from a specific TXT record which has a name `_rhinecert.[ZONE]`
2. Use the RCert to verify the signature of ZSK and the ZSK.
3. Use the ZSK to verify the signatures of other zone records.


## RoA Caching and RO bit
If RO bit is set in query(like DO bit for DNSSEC), meant that the resolver wants the authoritative nameserver to include its RoA in response. The resolver caches the RoA for zones. If resolver already has the RoA of the zone of queried name, it will not set RO bit.

DSP record helps to check if the resolver has the right RoA for specific zones. A DSP record of a zone contains an array of labels representing all delegated subzones. When checking the DSP for zone `EDU.` which consists `ISI`, the resolver knows that there exists subzone `ISI.EDU.`.

To illustate how resolver decides if RO bit need to be set, for example, with the name of question `C.ISI.EDU.`,
1. the resolver firstly checks its RoA cache if it cached the RoA of `C.ISI.EDU.`, if yes it knows it has the right RoA and doesn't need to set RO bit.
2. If not, it seek `ISI.EDU.` in its cache, if yes and then check the DSP of `ISI.EDU.`, if the DSP has label `C` then it knows that `C.ISI.EDU.` is delegated and it can't use the RoA of `ISI.EDU.` for `C.ISI.EDU.`, it breaks the search and set the RO bit.
3. If `ISI.EDU.` is in the cache and the DSP doesn't contain `C`, then it knows `C.ISI.EDU` is not delegated and just use the RoA in the cache.
4. If `ISI.EDU.` is also not in the cache, check for `EDU.