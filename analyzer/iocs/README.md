# IOC feeds

Put IOC files here (they are loaded automatically):

* `python3 -m droidtriage --update-iocs` downloads the public stalkerware list
  (AssoEchap/stalkerware-indicators) and the MVT spyware STIX2 feeds (Pegasus, Predator, …).
* Your own lists: `*.txt` with lines like `package:com.x`, `domain:evil.com`, `ip:1.2.3.4`,
  `sha256:<hash>`, `cert:<sha1 of signing cert>`.
