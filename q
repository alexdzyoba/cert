+ Do better format
+ Rewrite matchRoots to match by fingerprint or serial number.
+ Don't use x509.SystemCertPool(). Implement own method for getting system
  trust store. Look at the code in Go crypto/x509 package for that, it's
  just a trying of different files in /etc.

* Add root certificate (from system trust store) in dashed.
    * Unclear how to match issuer. There is no serial number or fingerprint of
      the issuer in the leaf certificate. Look how certificate chain is
      verified, it must use something to link certs. This convo suggests AIA and
      fetching issuer cert via link - https://chatgpt.com/c/68eccc65-d7f0-8328-9da5-44bd189c7df8
    * x509.Verify returns chains, one of the chains contains Root certificate,
      use it.
      * Why it shows as not verified :cry: ?

Fucking hell. The issuer matching is such a dumpster fire. It uses subject name,
then it searches a certificate in the list of roots by subject name. Then it
takes the issuer (root) and verifiy signatures which is good. But the search is
done using only subject name. Some certificates have Authority Key Id that is
set from Subject Key Id of issuer, more robust lookup, but it's an extension, so
not required and most of the roots don't have it!


* Refactoring
    * I don't like the types. Bundle and Certificate are weird. They should be
      easily converted from []*x509.Certificate and *x509.Certificate
    * The TextPrinter type is weird. I want to print adhoc in the code and I
      can't because I need to create it. Maybe make it global or add String
      method to Bundle?
    * I don't like how cumbersome the logic in main.

- Look at cross-signed certs, what is it, how to show it
