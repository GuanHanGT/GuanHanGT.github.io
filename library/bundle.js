!function e(t, n, r) {
    function i(a, s) {
        if (!n[a]) {
            if (!t[a]) {
                var u = "function" == typeof require && require;
                if (!s && u)
                    return u(a, !0);
                if (o)
                    return o(a, !0);
                var l = new Error("Cannot find module '" + a + "'");
                throw l.code = "MODULE_NOT_FOUND",
                l
            }
            var c = n[a] = {
                exports: {}
            };
            t[a][0].call(c.exports, (function(e) {
                return i(t[a][1][e] || e)
            }
            ), c, c.exports, e, t, n, r)
        }
        return n[a].exports
    }
    for (var o = "function" == typeof require && require, a = 0; a < r.length; a++)
        i(r[a]);
    return i
}({
    1: [function(e, t, n) {
        "use strict";
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var r = o(e("./element"))
          , i = o(e("./stream"));
        function o(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        function a(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        var s = function() {
            function e() {
                !function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, e)
            }
            var t, n, o;
            return t = e,
            o = [{
                key: "decode",
                value: function(e) {
                    try {
                        var t = new i.default(e);
                        return r.default.read(t)
                    } catch (e) {
                        throw console.error(e),
                        new Error("Could not decode ASN.1.")
                    }
                }
            }],
            (n = null) && a(t.prototype, n),
            o && a(t, o),
            e
        }();
        n.default = s
    }
    , {
        "./element": 2,
        "./stream": 5
    }],
    2: [function(e, t, n) {
        "use strict";
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var r = o(e("./tag"))
          , i = o(e("./stream"));
        o(e("../hex"));
        function o(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        function a(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        var s = function() {
            function e() {
                !function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, e),
                this.tag = null,
                this.length = 0,
                this.startIndex = 0,
                this.endIndex = 0,
                this.content = null,
                this.elements = []
            }
            var t, n, o;
            return t = e,
            o = [{
                key: "read",
                value: function(t) {
                    var n = new e;
                    if (n.startIndex = t.index,
                    n.tag = r.default.read(t),
                    n.length = e.readLength(t),
                    n.endIndex = t.index + n.length,
                    n.tag.constructed)
                        for (; t.index < n.endIndex; )
                            n.elements.push(e.read(t));
                    else
                        0 !== n.length && (n.content = t.read(n.length));
                    return n
                }
            }, {
                key: "readLength",
                value: function(e) {
                    var t = e.read()[0];
                    if (t >> 7 == 0)
                        return t;
                    if (128 === t)
                        return e.indexOfNextEOC() + 2;
                    var n = 127 & t;
                    return this.readLongLength(e, n)
                }
            }, {
                key: "readLongLength",
                value: function(e, t) {
                    for (var n = 0, r = 0; r < t; ++r)
                        n = 256 * n + e.read()[0];
                    return n
                }
            }],
            (n = [{
                key: "readAsConstructed",
                value: function() {
                    var t = arguments.length > 0 && void 0 !== arguments[0] && arguments[0]
                      , n = new i.default(this.content);
                    if (t) {
                        var r = n.read()[0];
                        if (0 !== r)
                            throw new Error("Leading byte is not 0.")
                    }
                    for (; n.index < this.length; )
                        this.elements.push(e.read(n))
                }
            }, {
                key: "findSubElement",
                value: function(e, t) {
                    for (var n = arguments.length > 2 && void 0 !== arguments[2] ? arguments[2] : 0, r = 0, i = 0; i < this.elements.length; i++)
                        if (this.elements[i].tag.number === t && this.elements[i].tag.class === n && ++r === e)
                            return this.elements[i];
                    return null
                }
            }]) && a(t.prototype, n),
            o && a(t, o),
            e
        }();
        n.default = s
    }
    , {
        "../hex": 25,
        "./stream": 5,
        "./tag": 6
    }],
    3: [function(e, t, n) {
        "use strict";
        function r(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        function i(e, t, n) {
            return t in e ? Object.defineProperty(e, t, {
                value: n,
                enumerable: !0,
                configurable: !0,
                writable: !0
            }) : e[t] = n,
            e
        }
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var o = function() {
            function e() {
                !function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, e)
            }
            var t, n, i;
            return t = e,
            i = [{
                key: "decode",
                value: function(e) {
                    try {
                        var t = []
                          , n = e[0] % 40;
                        t.push((e[0] - n) / 40),
                        t.push(n);
                        for (var r = 1; r < e.length; )
                            if (128 & e[r]) {
                                var i = [];
                                do {
                                    i.push(127 & e[r])
                                } while (128 & e[r++]);for (var o = 0, a = 0; a < i.length; a++)
                                    o = 128 * o + i[a];
                                t.push(o)
                            } else
                                t.push(e[r++]);
                        return t.join(".")
                    } catch (t) {
                        throw console.log(t),
                        new Error("Could not decode OID " + Hex.toHex(e))
                    }
                }
            }, {
                key: "getDescription",
                value: function(e, t) {
                    var n = t.get(e);
                    return n || e
                }
            }],
            (n = null) && r(t.prototype, n),
            i && r(t, i),
            e
        }();
        n.default = o,
        i(o, "SIGNATURE_ALGORITHMS", new Map([["1.2.840.113549.1.1.2", "md2WithRSAEncryption (PKCS #1)"], ["1.2.840.113549.1.1.3", "md4WithRSAEncryption (PKCS #1)"], ["1.2.840.113549.1.1.4", "md5WithRSAEncryption (PKCS #1)"], ["1.2.840.113549.1.1.5", "sha1WithRSAEncryption (PKCS #1)"], ["1.2.840.113549.1.1.14", "sha224WithRSAEncryption (PKCS #1)"], ["1.2.840.113549.1.1.11", "sha256WithRSAEncryption (PKCS #1)"], ["1.2.840.113549.1.1.12", "sha384WithRSAEncryption (PKCS #1)"], ["1.2.840.113549.1.1.13", "sha512WithRSAEncryption (PKCS #1)"], ["1.2.840.113549.1.1.10", "rsaPSS (PKCS #1)"], ["1.3.36.3.3.1.2", "rsaSignatureWithripemd160 (Teletrust signature algorithm)"], ["1.3.36.3.3.1.3", "rsaSignatureWithrimpemd128 (Teletrust signature algorithm)"], ["1.3.36.3.3.1.4", "rsaSignatureWithrimpemd256 (Teletrust signature algorithm)"], ["1.2.840.10040.4.3", "dsaWithSha1 (ANSI X9.57 algorithm)"], ["2.16.840.1.101.3.4.3.1", "dsaWithSha224 (NIST Algorithm)"], ["2.16.840.1.101.3.4.3.2", "dsaWithSha256 (NIST Algorithm)"], ["1.2.840.10045.4.3.1", "ecdsaWithSHA224 (ANSI X9.62 ECDSA algorithm with SHA1)"], ["1.2.840.10045.4.3.2", "ecdsaWithSHA256 (ANSI X9.62 ECDSA algorithm with SHA256)"], ["1.2.840.10045.4.3.3", "ecdsaWithSHA384 (ANSI X9.62 ECDSA algorithm with SHA384)"], ["1.2.840.10045.4.3.4", "ecdsaWithSHA512 (ANSI X9.62 ECDSA algorithm with SHA512)"], ["1.2.643.2.2.4", "gost94Signature (GOST R 34.10-94 + GOST R 34.11-94 signature. Obsoleted by GOST R 34.10-2001)"], ["1.2.643.2.2.3", "gostSignature (GOST R 34.10-2001 + GOST R 34.11-94 signature)"], ["1.3.14.3.2.29", "sha-1WithRSAEncryption (Oddball OIW OID)"], ["1.2.840.10045.4.1", "ecdsaWithSHA1 (ANSI X9.62 ECDSA algorithm with SHA1)"], ["1.2.840.113549.1.1.8", "pkcs1-MGF (PKCS #1)"]])),
        i(o, "RSA_KEY_TYPE_OID", "1.2.840.113549.1.1.1"),
        i(o, "DSA_KEY_TYPE_OID", "1.2.840.10040.4.1"),
        i(o, "EC_KEY_TYPE_OID", "1.2.840.10045.2.1"),
        i(o, "KEY_TYPES", new Map([[o.RSA_KEY_TYPE_OID, "rsaEncryption (PKCS #1)"], [o.DSA_KEY_TYPE_OID, "dsa (ANSI X9.57 algorithm)"], [o.EC_KEY_TYPE_OID, "ecPublicKey (ANSI X9.62 public key type)"]])),
        i(o, "EXT_KEY_USAGE_OID", "2.5.29.15"),
        i(o, "EXT_EXTENDED_KEY_USAGE_OID", "2.5.29.37"),
        i(o, "EXT_SUBJECT_ALT_NAME_OID", "2.5.29.17"),
        i(o, "EXT_AUTHORITY_KEY_IDENTIFIER_OID", "2.5.29.35"),
        i(o, "EXT_SUBJECT_KEY_IDENTIFIER_OID", "2.5.29.14"),
        i(o, "EXT_BASIC_CONSTRAINTS_OID", "2.5.29.19"),
        i(o, "EXTENSIONS", new Map([[o.EXT_KEY_USAGE_OID, "keyUsage"], [o.EXT_SUBJECT_ALT_NAME_OID, "subjectAltName"], [o.EXT_EXTENDED_KEY_USAGE_OID, "extKeyUsage"], [o.EXT_AUTHORITY_KEY_IDENTIFIER_OID, "authorityKeyIdentifier"], [o.EXT_SUBJECT_KEY_IDENTIFIER_OID, "subjectKeyIdentifier"], [o.EXT_BASIC_CONSTRAINTS_OID, "basicConstraints"]])),
        i(o, "EXTENDED_USAGES", new Map([["1.3.6.1.5.5.7.3.1", "serverAuth"], ["1.3.6.1.5.5.7.3.2", "clientAuth"], ["1.3.6.1.5.5.7.3.3", "codeSigning"], ["1.3.6.1.5.5.7.3.4", "emailProtection"], ["1.3.6.1.5.5.7.3.8", "timeStamping"], ["1.3.6.1.5.5.7.3.9", "OCSPSigning"]])),
        i(o, "DN_COMPONENT_CN", "2.5.4.3"),
        i(o, "DN_COMPONENTS", new Map([[o.DN_COMPONENT_CN, "CN"], ["2.5.4.4", "SN"], ["2.5.4.5", "SERIALNUMBER"], ["2.5.4.6", "C"], ["2.5.4.7", "L"], ["2.5.4.8", "ST"], ["2.5.4.9", "STREET"], ["2.5.4.10", "O"], ["2.5.4.11", "OU"], ["2.5.4.12", "T"], ["2.5.4.42", "G"], ["1.2.840.113549.1.9.1", "E"], ["0.9.2342.19200300.100.1.1", "UID"], ["0.9.2342.19200300.100.1.25", "DC"]]))
    }
    , {}],
    4: [function(e, t, n) {
        "use strict";
        function r(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var i = function() {
            function e() {
                !function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, e)
            }
            var t, n, i;
            return t = e,
            i = [{
                key: "decode",
                value: function(e) {
                    if (!e)
                        return "";
                    for (var t = "", n = 0; n < e.length; ++n)
                        t += String.fromCharCode(e[n]);
                    return t
                }
            }],
            (n = null) && r(t.prototype, n),
            i && r(t, i),
            e
        }();
        n.default = i
    }
    , {}],
    5: [function(e, t, n) {
        "use strict";
        function r(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var i = function() {
            function e(t) {
                !function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, e),
                this.array = t,
                this.index = 0
            }
            var t, n, i;
            return t = e,
            (n = [{
                key: "read",
                value: function() {
                    var e = arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : 1;
                    if (this.index + e > this.array.length)
                        throw new Error("Index out of bounds. (index: " + this.index + ", length: " + e + ", size: " + this.array.length);
                    var t = this.array.subarray(this.index, this.index + e);
                    return this.index += e,
                    t
                }
            }, {
                key: "indexOfNextEOC",
                value: function() {
                    for (var e = this.index; e < this.array.length - 1; e++)
                        if (this.isEOC(this.array[e]) && this.isEOC(this.array[e + 1]))
                            return e;
                    throw new Error("Could not find EOC octets.")
                }
            }, {
                key: "isEOC",
                value: function(e) {
                    return 0 === e
                }
            }]) && r(t.prototype, n),
            i && r(t, i),
            e
        }();
        n.default = i
    }
    , {}],
    6: [function(e, t, n) {
        "use strict";
        function r(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var i = function() {
            function e() {
                !function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, e),
                this.class = null,
                this.constructed = !1,
                this.number = null
            }
            var t, n, i;
            return t = e,
            i = [{
                key: "read",
                value: function(t) {
                    var n = new e
                      , r = t.read()[0];
                    return n.class = r >> 6,
                    n.constructed = 0 != (32 & r),
                    n.number = 31 & r,
                    31 == n.number && (n.number = e.readLongTagNumber(t)),
                    n
                }
            }, {
                key: "readLongTagNumber",
                value: function(e) {
                    var t, n = [];
                    do {
                        t = e.read(),
                        n.push(127 & t)
                    } while (128 & t);for (var r = 0, i = 0; i < n.length; i++)
                        r = 128 * r + n[i];
                    return r
                }
            }],
            (n = [{
                key: "isEqualTo",
                value: function(e) {
                    return this.class === e.class && this.constructed === e.constructed && this.number === e.number
                }
            }]) && r(t.prototype, n),
            i && r(t, i),
            e
        }();
        n.default = i
    }
    , {}],
    7: [function(e, t, n) {
        "use strict";
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var r, i = (r = e("./printable-string")) && r.__esModule ? r : {
            default: r
        };
        function o(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        function a(e, t, n) {
            return t in e ? Object.defineProperty(e, t, {
                value: n,
                enumerable: !0,
                configurable: !0,
                writable: !0
            }) : e[t] = n,
            e
        }
        var s = function() {
            function e() {
                !function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, e)
            }
            var t, n, r;
            return t = e,
            r = [{
                key: "decode",
                value: function(t) {
                    var n = arguments.length > 1 && void 0 !== arguments[1] && arguments[1]
                      , r = i.default.decode(t)
                      , o = (n ? e.GENERALIZED_TIME_PATTERN : e.UTC_TIME_PATTERN).exec(r);
                    if (!o)
                        throw new Error("Invalid date format.");
                    var a = "";
                    return a += (parseInt(o[1]) < 70 ? "20" : "19") + o[1] + "-",
                    a += o[2] + "-",
                    a += o[3],
                    a += "T",
                    a += o[4],
                    o[5] ? (a += ":" + o[5],
                    o[6] ? (a += ":" + o[6],
                    o[7] ? a += "." + o[7] : a += ".000") : a += ":00.000") : a += ":00:00.000",
                    o[8] && "Z" != o[8] ? (a += o[8].substring(0, 3),
                    o[9] ? a += ":" + o[9] : a += ":00") : a += "Z",
                    new Date(a)
                }
            }],
            (n = null) && o(t.prototype, n),
            r && o(t, r),
            e
        }();
        n.default = s,
        a(s, "UTC_TIME_PATTERN", /^(\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([01]\d|2[0-3])(?:([0-5]\d)(?:([0-5]\d)(?:[.,](\d{1,3}))?)?)?(Z|[-+](?:[0]\d|1[0-2])([0-5]\d)?)?$/),
        a(s, "GENERALIZED_TIME_PATTERN", /^(\d\d\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([01]\d|2[0-3])(?:([0-5]\d)(?:([0-5]\d)(?:[.,](\d{1,3}))?)?)?(Z|[-+](?:[0]\d|1[0-2])([0-5]\d)?)?$/)
    }
    , {
        "./printable-string": 4
    }],
    8: [function(e, t, n) {
        "use strict";
        function r(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var i = function() {
            function e() {
                !function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, e)
            }
            var t, n, i;
            return t = e,
            i = [{
                key: "decode",
                value: function(e) {
                    try {
                        for (var t = window.atob(e), n = t.length, r = new Uint8Array(new ArrayBuffer(n)), i = 0; i < n; i++)
                            r[i] = t.charCodeAt(i);
                        return r
                    } catch (e) {
                        throw console.error(e),
                        new Error("Could not decode Base64 string.")
                    }
                }
            }],
            (n = null) && r(t.prototype, n),
            i && r(t, i),
            e
        }();
        n.default = i
    }
    , {}],
    9: [function(e, t, n) {
        "use strict";
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var r = y(e("./hex"))
          , i = y(e("./asn1/oid"))
          , o = y(e("./distinguished-name"))
          , a = y(e("./asn1/time"))
          , s = y(e("./subject-public-key"))
          , u = y(e("./subject-public-key-rsa"))
          , l = y(e("./hashing/sha1"))
          , c = y(e("./hashing/sha256"))
          , f = y(e("./extensions/generic-extension"))
          , d = y(e("./extensions/subject-alt-name-extension"))
          , h = y(e("./extensions/key-usage-extension"))
          , b = y(e("./extensions/extended-key-usage-extension"))
          , v = y(e("./extensions/authority-key-identifier-extension"))
          , m = y(e("./extensions/subject-key-identifier-extension"))
          , p = y(e("./extensions/basic-constraints-extension"));
        function y(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        function g(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        var E = function() {
            function e(t) {
                !function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, e),
                this.rootElement = t,
                this.tbsElement = null,
                this.version = null,
                this.serialNumber = null,
                this.signatureAlgorithm = null,
                this.issuer = null,
                this.notBefore = null,
                this.notAfter = null,
                this.subject = null,
                this.subjectPublicKeyAlgorithm = null,
                this.subjectPublicKey = null,
                this.certificateSignatureAlgorithm = null,
                this.certificateSignatureValue = null,
                this.issuerUniqueId = null,
                this.subjectUniqueId = null,
                this.extensions = [],
                this.sha256FingerPrint = null,
                this.sha1FingerPrint = null
            }
            var t, n, y;
            return t = e,
            y = [{
                key: "fromElements",
                value: function(t, n) {
                    var r = new e(t);
                    if (0 == r.rootElement.elements.length)
                        throw new Error("Signature element does not contain any sub elements.");
                    if (r.tbsElement = r.rootElement.elements[0],
                    !r.tbsElement.tag.isEqualTo({
                        class: 0,
                        constructed: !0,
                        number: 16
                    }))
                        throw new Error("TBS element is not a sequence.");
                    return r.extractVersion(),
                    r.extractSerialNumber(),
                    r.extractSignatureAlgorithm(),
                    r.extractIssuer(),
                    r.extractValidity(),
                    r.extractSubject(),
                    r.extractSubjectPublicKeyInfo(),
                    r.extractCertificateSignature(),
                    r.extractCertificateSignatureValue(),
                    r.extractIssuerUniqueId(),
                    r.extractSubjectUniqueId(),
                    r.extractExtensions(),
                    r.calculateFingerprints(n),
                    r
                }
            }, {
                key: "getExtension",
                value: function(e, t, n) {
                    var r = null;
                    try {
                        switch (e) {
                        case i.default.EXT_SUBJECT_ALT_NAME_OID:
                            r = new d.default(e,t,n);
                            break;
                        case i.default.EXT_KEY_USAGE_OID:
                            r = new h.default(e,t,n);
                            break;
                        case i.default.EXT_EXTENDED_KEY_USAGE_OID:
                            r = new b.default(e,t,n);
                            break;
                        case i.default.EXT_AUTHORITY_KEY_IDENTIFIER_OID:
                            r = new v.default(e,t,n);
                            break;
                        case i.default.EXT_SUBJECT_KEY_IDENTIFIER_OID:
                            r = new m.default(e,t,n);
                            break;
                        case i.default.EXT_BASIC_CONSTRAINTS_OID:
                            r = new p.default(e,t,n);
                            break;
                        default:
                            r = new f.default(e,t,n)
                        }
                        r.parse()
                    } catch (i) {
                        console.log(i),
                        console.error("Could not parse extension with oid " + e),
                        (r = new f.default(e,t,n)).parse()
                    }
                    return r
                }
            }],
            (n = [{
                key: "extractVersion",
                value: function() {
                    try {
                        var e = this.tbsElement.elements[0];
                        if (!e || !e.tag.isEqualTo({
                            class: 2,
                            constructed: !0,
                            number: 0
                        }))
                            throw new Error("Could not find version element with tag number 0.");
                        var t = e.elements[0];
                        if (!t || !t.tag.isEqualTo({
                            class: 0,
                            constructed: !1,
                            number: 2
                        }))
                            throw new Error("Could not find integer element.");
                        switch (t.content[0]) {
                        case 0:
                            this.version = "v1";
                            break;
                        case 1:
                            this.version = "v2";
                            break;
                        case 2:
                            this.version = "v3";
                            break;
                        default:
                            this.version = "DEFAULT (v1)"
                        }
                    } catch (e) {
                        console.log(e),
                        console.error("Could not extract version number."),
                        this.version = "DEFAULT (v1)"
                    }
                }
            }, {
                key: "extractSerialNumber",
                value: function() {
                    try {
                        var e = this.tbsElement.findSubElement(1, 2);
                        if (!e || !e.tag.isEqualTo({
                            class: 0,
                            constructed: !1,
                            number: 2
                        }))
                            throw new Error("Could not find serial element.");
                        this.serialNumber = r.default.toHex(e.content)
                    } catch (e) {
                        console.log(e),
                        console.error("Could not extract serial number.")
                    }
                }
            }, {
                key: "extractSignatureAlgorithm",
                value: function() {
                    try {
                        var e = this.tbsElement.findSubElement(1, 16);
                        if (!e || !e.tag.isEqualTo({
                            class: 0,
                            constructed: !0,
                            number: 16
                        }))
                            throw new Error("Could not find signature element.");
                        var t = e.elements[0];
                        if (!t || !t.tag.isEqualTo({
                            class: 0,
                            constructed: !1,
                            number: 6
                        }))
                            throw new Error("Could not find OID element.");
                        var n = i.default.decode(t.content);
                        this.signatureAlgorithm = i.default.getDescription(n, i.default.SIGNATURE_ALGORITHMS)
                    } catch (e) {
                        console.log(e),
                        console.error("Could not extract signature algorithm.")
                    }
                }
            }, {
                key: "extractIssuer",
                value: function() {
                    try {
                        var e = this.tbsElement.findSubElement(2, 16);
                        if (!e || !e.tag.isEqualTo({
                            class: 0,
                            constructed: !0,
                            number: 16
                        }))
                            throw new Error("Could not find issuer element.");
                        this.issuer = o.default.fromSequence(e)
                    } catch (e) {
                        console.log(e),
                        console.error("Could not extract issuer.")
                    }
                }
            }, {
                key: "extractValidity",
                value: function() {
                    try {
                        var e = this.tbsElement.findSubElement(3, 16);
                        if (!e || !e.tag.isEqualTo({
                            class: 0,
                            constructed: !0,
                            number: 16
                        }))
                            throw new Error("Could not find validity element.");
                        var t = e.elements[0];
                        if (!t || !t.tag.isEqualTo({
                            class: 0,
                            constructed: !1,
                            number: 23
                        }) && !t.tag.isEqualTo({
                            class: 0,
                            constructed: !1,
                            number: 24
                        }))
                            throw new Error("Could not find notBefore element.");
                        var n = e.elements[1];
                        if (!n || !t.tag.isEqualTo({
                            class: 0,
                            constructed: !1,
                            number: 23
                        }) && !n.tag.isEqualTo({
                            class: 0,
                            constructed: !1,
                            number: 24
                        }))
                            throw new Error("Could not find notAfter element.");
                        this.notBefore = a.default.decode(t.content, 24 === t.tag.number),
                        this.notAfter = a.default.decode(n.content, 24 === n.tag.number)
                    } catch (e) {
                        console.log(e),
                        console.error("Could not extract validity.")
                    }
                }
            }, {
                key: "extractSubject",
                value: function() {
                    try {
                        var e = this.tbsElement.findSubElement(4, 16);
                        if (!e || !e.tag.isEqualTo({
                            class: 0,
                            constructed: !0,
                            number: 16
                        }))
                            throw new Error("Could not find subject element.");
                        this.subject = o.default.fromSequence(e)
                    } catch (e) {
                        console.log(e),
                        console.error("Could not extract subject.")
                    }
                }
            }, {
                key: "extractSubjectPublicKeyInfo",
                value: function() {
                    try {
                        var e = this.tbsElement.findSubElement(5, 16);
                        if (!e || !e.tag.isEqualTo({
                            class: 0,
                            constructed: !0,
                            number: 16
                        }))
                            throw new Error("Could not find public key info element.");
                        var t = e.elements[0];
                        if (!t || !t.tag.isEqualTo({
                            class: 0,
                            constructed: !0,
                            number: 16
                        }))
                            throw new Error("Could not find algorithm sequence element.");
                        var n = t.elements[0];
                        if (!n || !n.tag.isEqualTo({
                            class: 0,
                            constructed: !1,
                            number: 6
                        }))
                            throw new Error("Could not find OID element.");
                        var r = i.default.decode(n.content);
                        this.subjectPublicKeyAlgorithm = i.default.getDescription(r, i.default.KEY_TYPES);
                        var o = e.elements[1];
                        if (!o || !o.tag.isEqualTo({
                            class: 0,
                            constructed: !1,
                            number: 3
                        }))
                            throw new Error("Could not find public key element.");
                        r === i.default.RSA_KEY_TYPE_OID ? this.subjectPublicKey = u.default.fromElement(o) : this.subjectPublicKey = s.default.fromElement(o)
                    } catch (e) {
                        console.log(e),
                        console.error("Could not extract public key info.")
                    }
                }
            }, {
                key: "extractIssuerUniqueId",
                value: function() {
                    try {
                        var e = this.tbsElement.findSubElement(1, 1, 2);
                        if (!e || !e.tag.isEqualTo({
                            class: 2,
                            constructed: !0,
                            number: 1
                        }))
                            throw new Error("Could not find issuer unique id element with tag number 1.");
                        var t = e.elements[0];
                        if (!t || !t.tag.isEqualTo({
                            class: 0,
                            constructed: !1,
                            number: 3
                        }))
                            throw new Error("Could not find bit string element.");
                        var n = t.content;
                        n.length > 0 && 0 === n[0] && (n = n.slice(1, n.length)),
                        this.issuerUniqueId = r.default.toHex(n),
                        "v1" !== this.version && "DEFAULT (v1)" !== this.version || (this.version = "v2")
                    } catch (e) {}
                }
            }, {
                key: "extractSubjectUniqueId",
                value: function() {
                    try {
                        var e = this.tbsElement.findSubElement(1, 2, 2);
                        if (!e || !e.tag.isEqualTo({
                            class: 2,
                            constructed: !0,
                            number: 2
                        }))
                            throw new Error("Could not find subject unique id element with tag number 2.");
                        var t = e.elements[0];
                        if (!t || !t.tag.isEqualTo({
                            class: 0,
                            constructed: !1,
                            number: 3
                        }))
                            throw new Error("Could not find bit string element.");
                        var n = t.content;
                        n.length > 0 && 0 === n[0] && (n = n.slice(1, n.length)),
                        this.subjectUniqueId = r.default.toHex(n),
                        "v1" !== this.version && "DEFAULT (v1)" !== this.version || (this.version = "v2")
                    } catch (e) {}
                }
            }, {
                key: "extractExtensions",
                value: function() {
                    try {
                        var t = this.tbsElement.findSubElement(1, 3, 2);
                        if (!t || !t.tag.isEqualTo({
                            class: 2,
                            constructed: !0,
                            number: 3
                        }))
                            throw new Error("Could not find extensions element with tag number 3.");
                        var n = t.elements[0];
                        if (!n || !n.tag.isEqualTo({
                            class: 0,
                            constructed: !0,
                            number: 16
                        }))
                            throw new Error("Could not find extensions sequence.");
                        "v1" !== this.version && "v2" !== this.version && "DEFAULT (v1)" !== this.version || (this.version = "v3");
                        for (var r = 0; r < n.elements.length; r++) {
                            var o = n.elements[r]
                              , a = o.elements[0];
                            if (!a || !a.tag.isEqualTo({
                                class: 0,
                                constructed: !1,
                                number: 6
                            }))
                                throw new Error("Could not find OID element.");
                            var s = i.default.decode(a.content)
                              , u = !1
                              , l = !1;
                            o.elements[1] && o.elements[1].tag.isEqualTo({
                                class: 0,
                                constructed: !1,
                                number: 1
                            }) && (l = !0,
                            u = 255 === o.elements[1].content[0]);
                            var c = l ? 2 : 1
                              , f = o.elements[c];
                            if (!f || !f.tag.isEqualTo({
                                class: 0,
                                constructed: !1,
                                number: 4
                            }))
                                throw new Error("Could not find octet string element.");
                            var d = e.getExtension(s, u, f);
                            this.extensions.push(d)
                        }
                    } catch (e) {
                        console.log(e),
                        console.error("Could not extract certificate extensions.")
                    }
                }
            }, {
                key: "extractCertificateSignature",
                value: function() {
                    try {
                        var e = this.rootElement.elements[1];
                        if (!e || !e.tag.isEqualTo({
                            class: 0,
                            constructed: !0,
                            number: 16
                        }))
                            throw new Error("Could not find certificate signature element.");
                        var t = e.elements[0];
                        if (!t || !t.tag.isEqualTo({
                            class: 0,
                            constructed: !1,
                            number: 6
                        }))
                            throw new Error("Could not find OID element.");
                        var n = i.default.decode(t.content);
                        this.certificateSignatureAlgorithm = i.default.getDescription(n, i.default.SIGNATURE_ALGORITHMS)
                    } catch (e) {
                        console.log(e),
                        console.error("Could not extract certificate signature algorithm.")
                    }
                }
            }, {
                key: "extractCertificateSignatureValue",
                value: function() {
                    try {
                        var e = this.rootElement.elements[2];
                        if (!e || !e.tag.isEqualTo({
                            class: 0,
                            constructed: !1,
                            number: 3
                        }))
                            throw new Error("Could not find signature element.");
                        var t = e.content;
                        t.length > 0 && 0 === t[0] && (t = t.slice(1, t.length)),
                        this.certificateSignatureValue = r.default.toHex(t)
                    } catch (e) {
                        console.log(e),
                        console.error("Could not extract certificate signature algorithm.")
                    }
                }
            }, {
                key: "calculateFingerprints",
                value: function(e) {
                    this.sha1FingerPrint = r.default.toHex((new l.default).update(e).digest()),
                    this.sha256FingerPrint = r.default.toHex((new c.default).update(e).digest())
                }
            }]) && g(t.prototype, n),
            y && g(t, y),
            e
        }();
        n.default = E
    }
    , {
        "./asn1/oid": 3,
        "./asn1/time": 7,
        "./distinguished-name": 14,
        "./extensions/authority-key-identifier-extension": 16,
        "./extensions/basic-constraints-extension": 17,
        "./extensions/extended-key-usage-extension": 18,
        "./extensions/generic-extension": 19,
        "./extensions/key-usage-extension": 20,
        "./extensions/subject-alt-name-extension": 21,
        "./extensions/subject-key-identifier-extension": 22,
        "./hashing/sha1": 23,
        "./hashing/sha256": 24,
        "./hex": 25,
        "./subject-public-key": 29,
        "./subject-public-key-rsa": 28
    }],
    10: [function(e, t, n) {
        "use strict";
        function r(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var i = function() {
            function e() {
                !function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, e)
            }
            var t, n, i;
            return t = e,
            i = [{
                key: "copy",
                value: function(e) {
                    if (window.clipboardData && window.clipboardData.setData)
                        return window.clipboardData.setData("Text", e);
                    if (document.queryCommandSupported && document.queryCommandSupported("copy")) {
                        var t = document.createElement("textarea");
                        t.textContent = e,
                        t.style.position = "fixed",
                        document.body.appendChild(t),
                        t.select();
                        try {
                            return document.execCommand("copy")
                        } catch (e) {
                            return console.warn("Copy to clipboard failed.", e),
                            !1
                        } finally {
                            document.body.removeChild(t)
                        }
                    }
                }
            }],
            (n = null) && r(t.prototype, n),
            i && r(t, i),
            e
        }();
        n.default = i
    }
    , {}],
    11: [function(e, t, n) {
        "use strict";
        var r = e("./cookies.js");
        t.exports = function() {
            return {
                init: function() {
                    $((function() {
                        var e = $(".consent")
                          , t = $(".consent .accept");
                        e.offsetHeight,
                        r().get("consent") || e.addClass("show"),
                        t.click((function() {
                            r().set("consent", !0),
                            e.removeClass("show")
                        }
                        ))
                    }
                    ))
                }
            }
        }
    }
    , {
        "./cookies.js": 12
    }],
    12: [function(e, t, n) {
        "use strict";
        t.exports = function() {
            return {
                set: function(e, t) {
                    var n = new Date;
                    n.setTime(n.getTime() + 31536e6);
                    var r = "; expires=" + n.toGMTString();
                    document.cookie = e + "=" + t + r + "; path=/"
                },
                get: function(e, t) {
                    for (var n = e + "=", r = document.cookie.split(";"), i = 0; i < r.length; i++) {
                        for (var o = r[i]; " " == o.charAt(0); )
                            o = o.substring(1, o.length);
                        if (0 == o.indexOf(n))
                            return o.substring(n.length, o.length)
                    }
                    return t
                }
            }
        }
    }
    , {}],
    13: [function(e, t, n) {
        "use strict";
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var r = a(e("./base64"))
          , i = a(e("./asn1/asn1"))
          , o = a(e("./certificate"));
        function a(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        function s(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        function u(e, t, n) {
            return t in e ? Object.defineProperty(e, t, {
                value: n,
                enumerable: !0,
                configurable: !0,
                writable: !0
            }) : e[t] = n,
            e
        }
        var l = function() {
            function e() {
                !function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, e)
            }
            var t, n, a;
            return t = e,
            a = [{
                key: "decode",
                value: function(t) {
                    return e.validate(t),
                    t.match(this.PEM_MATCH_PATTERN).map((function(t) {
                        return e.decodeCertificate(t)
                    }
                    ))
                }
            }, {
                key: "decodeCertificate",
                value: function(t) {
                    var n = e.cleanup(t)
                      , a = r.default.decode(n)
                      , s = i.default.decode(a);
                    return o.default.fromElements(s, a)
                }
            }, {
                key: "validate",
                value: function(e) {
                    if (!this.PEM_VALIDATION_PATTERN.test(e))
                        throw new Error("Invalid PEM format.")
                }
            }, {
                key: "cleanup",
                value: function(e) {
                    return e.replace(this.CLEANUP_PATTERN, "")
                }
            }],
            (n = null) && s(t.prototype, n),
            a && s(t, a),
            e
        }();
        n.default = l,
        u(l, "PEM_VALIDATION_PATTERN", /^([\t-\r \xA0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000\uFEFF]*\x2D{5}BEGIN CERTIFICATE\x2D{5}[\t-\r \+\/-9=A-Za-z\xA0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000\uFEFF]*\x2D{5}END CERTIFICATE\x2D{5}[\t-\r \xA0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000\uFEFF]*)+$/),
        u(l, "PEM_MATCH_PATTERN", /\x2D{5}BEGIN CERTIFICATE\x2D{5}[\s\S]*?\x2D{5}END CERTIFICATE\x2D{5}/g),
        u(l, "CLEANUP_PATTERN", /(-----(BEGIN|END) CERTIFICATE-----|[\n\r\s])/g)
    }
    , {
        "./asn1/asn1": 1,
        "./base64": 8,
        "./certificate": 9
    }],
    14: [function(e, t, n) {
        "use strict";
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var r = o(e("./asn1/oid"))
          , i = o(e("./asn1/printable-string"));
        function o(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        function a(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        var s = function() {
            function e() {
                !function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, e),
                this.components = new Map,
                this.commonName = null
            }
            var t, n, o;
            return t = e,
            o = [{
                key: "fromSequence",
                value: function(t) {
                    var n = new e;
                    return n.components = e.extractComponents(t),
                    n.commonName = n.components.get(r.default.DN_COMPONENT_CN),
                    n
                }
            }, {
                key: "extractComponents",
                value: function(e) {
                    for (var t = new Map, n = 0; n < e.elements.length; n++) {
                        var o = e.elements[n];
                        if (!o || !o.tag.isEqualTo({
                            class: 0,
                            constructed: !0,
                            number: 17
                        }))
                            throw new Error("Element is not a set.");
                        var a = o.elements[0];
                        if (!a || !a.tag.isEqualTo({
                            class: 0,
                            constructed: !0,
                            number: 16
                        }))
                            throw new Error("Set does not contain a sequence.");
                        var s = a.elements[0];
                        if (!s || !s.tag.isEqualTo({
                            class: 0,
                            constructed: !1,
                            number: 6
                        }))
                            throw new Error("Sequence does not contain an OID.");
                        var u = a.elements[1];
                        if (!u || !u.tag.isEqualTo({
                            class: 0,
                            constructed: !1,
                            number: 19
                        }) && !u.tag.isEqualTo({
                            class: 0,
                            constructed: !1,
                            number: 12
                        }) && !u.tag.isEqualTo({
                            class: 0,
                            constructed: !1,
                            number: 22
                        }))
                            throw new Error("Sequence does not contain a string.");
                        var l = r.default.decode(s.content)
                          , c = i.default.decode(u.content);
                        t.set(l, c)
                    }
                    return t
                }
            }],
            (n = [{
                key: "toString",
                value: function() {
                    var e = "";
                    return this.components.forEach((function(t, n) {
                        return e += r.default.DN_COMPONENTS.get(n) + "=" + t + ", "
                    }
                    )),
                    e.replace(/[,\s]*$/, "")
                }
            }]) && a(t.prototype, n),
            o && a(t, o),
            e
        }();
        n.default = s
    }
    , {
        "./asn1/oid": 3,
        "./asn1/printable-string": 4
    }],
    15: [function(e, t, n) {
        "use strict";
        var r = u(e("./consent.js"))
          , i = u(e("./share.js"))
          , o = u(e("./decoder.js"))
          , a = u(e("./results-generator"))
          , s = u(e("./clipboard"));
        function u(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        $((function() {
            (0,
            r.default)().init(),
            window.share = new i.default;
            var e = $("#certificate");
            function t() {
                $("#error").hide(),
                $("#upload-error").hide(),
                $("#cert-info-warn").hide();
                var t = e.val();
                try {
                    var n = o.default.decode(t);
                    a.default.generate($("#results"), n),
                    _dev ? console.log("Engagement: decode") : gtag("event", "decode", {
                        event_category: "Engagement"
                    })
                } catch (e) {
                    console.log(e),
                    $("#error-message").text(e),
                    $("#error").show()
                }
                $("#decode").removeAttr("disabled")
            }
            function n(t) {
                e.val("");
                for (var n = function(n) {
                    if (t[n].size > 1048576)
                        return console.error("File is too large. (Max 1MB)"),
                        $("#upload-error-message").text("File " + t[n].name + " is too large. (Max 1MB)"),
                        $("#upload-error").show(),
                        "break";
                    var r = new FileReader;
                    r.onload = function(r) {
                        if (!r.target.result.startsWith("-"))
                            return console.error("File is not a PEM file."),
                            $("#upload-error-message").text("File " + t[n].name + " is not a PEM file."),
                            void $("#upload-error").show();
                        e.val(e.val() + r.target.result)
                    }
                    ,
                    r.readAsText(t[n])
                }, r = 0; r < t.length; r++) {
                    if ("break" === n(r))
                        break
                }
            }
            function u(e) {
                e.preventDefault(),
                e.stopPropagation()
            }
            $("#form").submit((function(e) {
                u(e),
                $("#decode").prop("disabled", !0),
                setTimeout(t, 10)
            }
            )),
            $("#show-sample").click((function(e) {
                u(e),
                fetch("sample.pem").then((function(e) {
                    return e.text()
                }
                )).then((function(e) {
                    return $("#certificate").val(e)
                }
                ))
            }
            )),
            $("#copy").click((function(t) {
                u(t),
                s.default.copy(e.val())
            }
            )),
            $("#clear").click((function(t) {
                u(t),
                $("#upload-error").hide(),
                e.val("")
            }
            )),
            $("#upload").click((function(e) {
                u(e),
                $("#upload-error").hide(),
                $("#uploadFile").click()
            }
            )),
            $("#uploadFile").change((function(e) {
                n(e.target.files)
            }
            )),
            e.on("dragover", (function(t) {
                u(t),
                e.addClass("dragging")
            }
            )),
            e.on("dragleave", (function(t) {
                u(t),
                e.removeClass("dragging")
            }
            )),
            e.on("drop", (function(t) {
                u(t),
                e.removeClass("dragging"),
                $("#upload-error").hide(),
                n(t.originalEvent.dataTransfer.files)
            }
            ))
        }
        ))
    }
    , {
        "./clipboard": 10,
        "./consent.js": 11,
        "./decoder.js": 13,
        "./results-generator": 26,
        "./share.js": 27
    }],
    16: [function(e, t, n) {
        "use strict";
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var r = o(e("../hex"))
          , i = o(e("../asn1/oid"));
        function o(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        function a(e) {
            return (a = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(e) {
                return typeof e
            }
            : function(e) {
                return e && "function" == typeof Symbol && e.constructor === Symbol && e !== Symbol.prototype ? "symbol" : typeof e
            }
            )(e)
        }
        function s(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        function u(e, t) {
            return !t || "object" !== a(t) && "function" != typeof t ? function(e) {
                if (void 0 === e)
                    throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
                return e
            }(e) : t
        }
        function l(e) {
            return (l = Object.setPrototypeOf ? Object.getPrototypeOf : function(e) {
                return e.__proto__ || Object.getPrototypeOf(e)
            }
            )(e)
        }
        function c(e, t) {
            return (c = Object.setPrototypeOf || function(e, t) {
                return e.__proto__ = t,
                e
            }
            )(e, t)
        }
        var f = function(e) {
            function t(e, n, r) {
                return function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, t),
                u(this, l(t).call(this, e, n, r))
            }
            var n, o, a;
            return function(e, t) {
                if ("function" != typeof t && null !== t)
                    throw new TypeError("Super expression must either be null or a function");
                e.prototype = Object.create(t && t.prototype, {
                    constructor: {
                        value: e,
                        writable: !0,
                        configurable: !0
                    }
                }),
                t && c(e, t)
            }(t, e),
            n = t,
            (o = [{
                key: "parse",
                value: function() {
                    this.name = i.default.getDescription(this.oid, i.default.EXTENSIONS),
                    this.element.readAsConstructed();
                    var e = this.element.elements[0];
                    if (!e || !e.tag.isEqualTo({
                        class: 0,
                        constructed: !0,
                        number: 16
                    }))
                        throw new Error("Could not find sequence element.");
                    this.value = "";
                    var t = e.findSubElement(1, 0, 2);
                    t && (this.value += "keyIdentifier: " + r.default.toHex(t.content) + "\r\n");
                    var n = e.findSubElement(1, 1, 2);
                    n && (this.value += "authorityCertIssuer: " + r.default.toHex(n.content) + "\r\n");
                    var o = e.findSubElement(1, 2, 2);
                    o && (this.value += "authorityCertSerialNumber: " + r.default.toHex(o.content) + "\r\n"),
                    this.value = this.value.trim()
                }
            }]) && s(n.prototype, o),
            a && s(n, a),
            t
        }(o(e("./generic-extension")).default);
        n.default = f
    }
    , {
        "../asn1/oid": 3,
        "../hex": 25,
        "./generic-extension": 19
    }],
    17: [function(e, t, n) {
        "use strict";
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var r = i(e("../asn1/oid"));
        function i(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        function o(e) {
            return (o = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(e) {
                return typeof e
            }
            : function(e) {
                return e && "function" == typeof Symbol && e.constructor === Symbol && e !== Symbol.prototype ? "symbol" : typeof e
            }
            )(e)
        }
        function a(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        function s(e, t) {
            return !t || "object" !== o(t) && "function" != typeof t ? function(e) {
                if (void 0 === e)
                    throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
                return e
            }(e) : t
        }
        function u(e) {
            return (u = Object.setPrototypeOf ? Object.getPrototypeOf : function(e) {
                return e.__proto__ || Object.getPrototypeOf(e)
            }
            )(e)
        }
        function l(e, t) {
            return (l = Object.setPrototypeOf || function(e, t) {
                return e.__proto__ = t,
                e
            }
            )(e, t)
        }
        var c = function(e) {
            function t(e, n, r) {
                return function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, t),
                s(this, u(t).call(this, e, n, r))
            }
            var n, i, o;
            return function(e, t) {
                if ("function" != typeof t && null !== t)
                    throw new TypeError("Super expression must either be null or a function");
                e.prototype = Object.create(t && t.prototype, {
                    constructor: {
                        value: e,
                        writable: !0,
                        configurable: !0
                    }
                }),
                t && l(e, t)
            }(t, e),
            n = t,
            (i = [{
                key: "parse",
                value: function() {
                    if (this.name = r.default.getDescription(this.oid, r.default.EXTENSIONS),
                    !this.element.tag.isEqualTo({
                        class: 0,
                        constructed: !1,
                        number: 4
                    }))
                        throw new Error("Element is not an octet string.");
                    this.element.readAsConstructed();
                    var e = this.element.elements[0];
                    if (!e || !e.tag.isEqualTo({
                        class: 0,
                        constructed: !0,
                        number: 16
                    }))
                        throw new Error("Could not find sequence element.");
                    this.value = "";
                    var t = !1
                      , n = e.findSubElement(1, 1);
                    n && 255 === n.content[0] && (t = !0),
                    this.value += "ca: " + t + "\r\n";
                    var i = t ? "Unlimited" : "None"
                      , o = e.findSubElement(1, 2);
                    o && (i = o.content[0]),
                    this.value += "pathLenConstraint: " + i
                }
            }]) && a(n.prototype, i),
            o && a(n, o),
            t
        }(i(e("./generic-extension")).default);
        n.default = c
    }
    , {
        "../asn1/oid": 3,
        "./generic-extension": 19
    }],
    18: [function(e, t, n) {
        "use strict";
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var r = o(e("./generic-extension"))
          , i = o(e("../asn1/oid"));
        o(e("../hex")),
        o(e("../asn1/printable-string"));
        function o(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        function a(e) {
            return (a = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(e) {
                return typeof e
            }
            : function(e) {
                return e && "function" == typeof Symbol && e.constructor === Symbol && e !== Symbol.prototype ? "symbol" : typeof e
            }
            )(e)
        }
        function s(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        function u(e, t) {
            return !t || "object" !== a(t) && "function" != typeof t ? function(e) {
                if (void 0 === e)
                    throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
                return e
            }(e) : t
        }
        function l(e) {
            return (l = Object.setPrototypeOf ? Object.getPrototypeOf : function(e) {
                return e.__proto__ || Object.getPrototypeOf(e)
            }
            )(e)
        }
        function c(e, t) {
            return (c = Object.setPrototypeOf || function(e, t) {
                return e.__proto__ = t,
                e
            }
            )(e, t)
        }
        var f = function(e) {
            function t(e, n, r) {
                return function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, t),
                u(this, l(t).call(this, e, n, r))
            }
            var n, r, o;
            return function(e, t) {
                if ("function" != typeof t && null !== t)
                    throw new TypeError("Super expression must either be null or a function");
                e.prototype = Object.create(t && t.prototype, {
                    constructor: {
                        value: e,
                        writable: !0,
                        configurable: !0
                    }
                }),
                t && c(e, t)
            }(t, e),
            n = t,
            (r = [{
                key: "parse",
                value: function() {
                    if (this.name = i.default.getDescription(this.oid, i.default.EXTENSIONS),
                    !this.element.tag.isEqualTo({
                        class: 0,
                        constructed: !1,
                        number: 4
                    }))
                        throw new Error("Element is not an octet string");
                    this.element.readAsConstructed();
                    var e = this.element.elements[0];
                    if (!e || !e.tag.isEqualTo({
                        class: 0,
                        constructed: !0,
                        number: 16
                    }))
                        throw new Error("Could not find sequence element.");
                    this.value = "";
                    for (var t = 0; t < e.elements.length; t++) {
                        var n = e.elements[t];
                        if (!n.tag.isEqualTo({
                            class: 0,
                            constructed: !1,
                            number: 6
                        }))
                            throw new Error("Element is not OID at index: " + t);
                        var r = i.default.decode(n.content);
                        this.value += i.default.getDescription(r, i.default.EXTENDED_USAGES) + "\r\n"
                    }
                    this.value = this.value.trim()
                }
            }]) && s(n.prototype, r),
            o && s(n, o),
            t
        }(r.default);
        n.default = f
    }
    , {
        "../asn1/oid": 3,
        "../asn1/printable-string": 4,
        "../hex": 25,
        "./generic-extension": 19
    }],
    19: [function(e, t, n) {
        "use strict";
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var r = o(e("../hex"))
          , i = o(e("../asn1/oid"));
        function o(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        function a(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        var s = function() {
            function e(t, n, r) {
                !function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, e),
                this.oid = t,
                this.critical = n,
                this.element = r,
                this.name = t,
                this.value = null
            }
            var t, n, o;
            return t = e,
            (n = [{
                key: "parse",
                value: function() {
                    this.name = i.default.getDescription(this.oid, i.default.EXTENSIONS),
                    this.value = r.default.toHex(this.element.content)
                }
            }]) && a(t.prototype, n),
            o && a(t, o),
            e
        }();
        n.default = s
    }
    , {
        "../asn1/oid": 3,
        "../hex": 25
    }],
    20: [function(e, t, n) {
        "use strict";
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var r = o(e("./generic-extension"))
          , i = o(e("../asn1/oid"));
        o(e("../hex")),
        o(e("../asn1/printable-string"));
        function o(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        function a(e) {
            return (a = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(e) {
                return typeof e
            }
            : function(e) {
                return e && "function" == typeof Symbol && e.constructor === Symbol && e !== Symbol.prototype ? "symbol" : typeof e
            }
            )(e)
        }
        function s(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        function u(e, t) {
            return !t || "object" !== a(t) && "function" != typeof t ? function(e) {
                if (void 0 === e)
                    throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
                return e
            }(e) : t
        }
        function l(e) {
            return (l = Object.setPrototypeOf ? Object.getPrototypeOf : function(e) {
                return e.__proto__ || Object.getPrototypeOf(e)
            }
            )(e)
        }
        function c(e, t) {
            return (c = Object.setPrototypeOf || function(e, t) {
                return e.__proto__ = t,
                e
            }
            )(e, t)
        }
        var f = function(e) {
            function t(e, n, r) {
                return function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, t),
                u(this, l(t).call(this, e, n, r))
            }
            var n, r, o;
            return function(e, t) {
                if ("function" != typeof t && null !== t)
                    throw new TypeError("Super expression must either be null or a function");
                e.prototype = Object.create(t && t.prototype, {
                    constructor: {
                        value: e,
                        writable: !0,
                        configurable: !0
                    }
                }),
                t && c(e, t)
            }(t, e),
            n = t,
            (r = [{
                key: "parse",
                value: function() {
                    if (this.name = i.default.getDescription(this.oid, i.default.EXTENSIONS),
                    !this.element.tag.isEqualTo({
                        class: 0,
                        constructed: !1,
                        number: 4
                    }))
                        throw new Error("Element is not an octet string");
                    this.element.readAsConstructed();
                    var e = this.element.elements[0];
                    if (!e || !e.tag.isEqualTo({
                        class: 0,
                        constructed: !1,
                        number: 3
                    }))
                        throw new Error("Could not find bit string element.");
                    if (e.content.length < 2)
                        throw new Error("Bit string length is : " + e.content.length);
                    this.value = "";
                    var t = e.content[1];
                    this.mask(t, 7) && (this.value += "digitalSignature\r\n"),
                    this.mask(t, 6) && (this.value += "nonRepudiation\r\n"),
                    this.mask(t, 5) && (this.value += "keyEncipherment\r\n"),
                    this.mask(t, 4) && (this.value += "dataEncipherment\r\n"),
                    this.mask(t, 3) && (this.value += "keyAgreement\r\n"),
                    this.mask(t, 2) && (this.value += "keyCertSign\r\n"),
                    this.mask(t, 1) && (this.value += "cRLSign\r\n"),
                    this.mask(t, 0) && (this.value += "encipherOnly\r\n"),
                    this.mask(t, 15) && (this.value += "decipherOnly\r\n"),
                    this.value = this.value.trim()
                }
            }, {
                key: "mask",
                value: function(e, t) {
                    return Boolean(1 << t & e)
                }
            }]) && s(n.prototype, r),
            o && s(n, o),
            t
        }(r.default);
        n.default = f
    }
    , {
        "../asn1/oid": 3,
        "../asn1/printable-string": 4,
        "../hex": 25,
        "./generic-extension": 19
    }],
    21: [function(e, t, n) {
        "use strict";
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var r = s(e("./generic-extension"))
          , i = s(e("../asn1/oid"))
          , o = s(e("../hex"))
          , a = s(e("../asn1/printable-string"));
        function s(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        function u(e) {
            return (u = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(e) {
                return typeof e
            }
            : function(e) {
                return e && "function" == typeof Symbol && e.constructor === Symbol && e !== Symbol.prototype ? "symbol" : typeof e
            }
            )(e)
        }
        function l(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        function c(e, t) {
            return !t || "object" !== u(t) && "function" != typeof t ? function(e) {
                if (void 0 === e)
                    throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
                return e
            }(e) : t
        }
        function f(e) {
            return (f = Object.setPrototypeOf ? Object.getPrototypeOf : function(e) {
                return e.__proto__ || Object.getPrototypeOf(e)
            }
            )(e)
        }
        function d(e, t) {
            return (d = Object.setPrototypeOf || function(e, t) {
                return e.__proto__ = t,
                e
            }
            )(e, t)
        }
        var h = function(e) {
            function t(e, n, r) {
                return function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, t),
                c(this, f(t).call(this, e, n, r))
            }
            var n, r, s;
            return function(e, t) {
                if ("function" != typeof t && null !== t)
                    throw new TypeError("Super expression must either be null or a function");
                e.prototype = Object.create(t && t.prototype, {
                    constructor: {
                        value: e,
                        writable: !0,
                        configurable: !0
                    }
                }),
                t && d(e, t)
            }(t, e),
            n = t,
            (r = [{
                key: "parse",
                value: function() {
                    this.name = i.default.getDescription(this.oid, i.default.EXTENSIONS),
                    this.element.readAsConstructed(!1);
                    var e = this.element.elements[0];
                    if (!e || !e.tag.isEqualTo({
                        class: 0,
                        constructed: !0,
                        number: 16
                    }))
                        throw new Error("Could not find sequence element.");
                    this.value = "";
                    for (var t = 0; t < e.elements.length; t++) {
                        var n = e.elements[t]
                          , r = null
                          , s = null;
                        try {
                            switch (n.tag.number) {
                            case 0:
                                r = "otherName",
                                s = o.default.toHex(n.content);
                                break;
                            case 1:
                                r = "rfc822Name",
                                s = a.default.decode(n.content);
                                break;
                            case 2:
                                r = "dNSName",
                                s = a.default.decode(n.content);
                                break;
                            case 3:
                                r = "x400Address",
                                s = o.default.toHex(n.content);
                                break;
                            case 4:
                                r = "directoryName",
                                s = o.default.toHex(n.content);
                                break;
                            case 5:
                                r = "ediPartyName",
                                s = o.default.toHex(n.content);
                                break;
                            case 6:
                                r = "uniformResourceIdentifier",
                                s = a.default.decode(n.content);
                                break;
                            case 7:
                                r = "iPAddress",
                                s = a.default.decode(n.content);
                                break;
                            case 8:
                                r = "registeredID",
                                s = i.default.decode(n.content);
                                break;
                            default:
                                r = "Unknown [" + n.tag.number + "]",
                                s = o.default.toHex(n.content)
                            }
                        } catch (e) {
                            r || (r = "Error [" + n.tag.number + "]"),
                            s = "Error"
                        }
                        this.value += r + ": " + s + "\r\n"
                    }
                    this.value = this.value.trim()
                }
            }]) && l(n.prototype, r),
            s && l(n, s),
            t
        }(r.default);
        n.default = h
    }
    , {
        "../asn1/oid": 3,
        "../asn1/printable-string": 4,
        "../hex": 25,
        "./generic-extension": 19
    }],
    22: [function(e, t, n) {
        "use strict";
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var r = o(e("../hex"))
          , i = o(e("../asn1/oid"));
        function o(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        function a(e) {
            return (a = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(e) {
                return typeof e
            }
            : function(e) {
                return e && "function" == typeof Symbol && e.constructor === Symbol && e !== Symbol.prototype ? "symbol" : typeof e
            }
            )(e)
        }
        function s(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        function u(e, t) {
            return !t || "object" !== a(t) && "function" != typeof t ? function(e) {
                if (void 0 === e)
                    throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
                return e
            }(e) : t
        }
        function l(e) {
            return (l = Object.setPrototypeOf ? Object.getPrototypeOf : function(e) {
                return e.__proto__ || Object.getPrototypeOf(e)
            }
            )(e)
        }
        function c(e, t) {
            return (c = Object.setPrototypeOf || function(e, t) {
                return e.__proto__ = t,
                e
            }
            )(e, t)
        }
        var f = function(e) {
            function t(e, n, r) {
                return function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, t),
                u(this, l(t).call(this, e, n, r))
            }
            var n, o, a;
            return function(e, t) {
                if ("function" != typeof t && null !== t)
                    throw new TypeError("Super expression must either be null or a function");
                e.prototype = Object.create(t && t.prototype, {
                    constructor: {
                        value: e,
                        writable: !0,
                        configurable: !0
                    }
                }),
                t && c(e, t)
            }(t, e),
            n = t,
            (o = [{
                key: "parse",
                value: function() {
                    this.name = i.default.getDescription(this.oid, i.default.EXTENSIONS),
                    this.element.readAsConstructed();
                    var e = this.element.elements[0];
                    if (!e || !e.tag.isEqualTo({
                        class: 0,
                        constructed: !1,
                        number: 4
                    }))
                        throw new Error("Could not find octet string element.");
                    this.value = r.default.toHex(e.content)
                }
            }]) && s(n.prototype, o),
            a && s(n, a),
            t
        }(o(e("./generic-extension")).default);
        n.default = f
    }
    , {
        "../asn1/oid": 3,
        "../hex": 25,
        "./generic-extension": 19
    }],
    23: [function(e, t, n) {
        "use strict";
        function r(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        function i(e, t, n) {
            return t in e ? Object.defineProperty(e, t, {
                value: n,
                enumerable: !0,
                configurable: !0,
                writable: !0
            }) : e[t] = n,
            e
        }
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var o = function() {
            function e() {
                !function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, e),
                this.blocks = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                this.h0 = 1732584193,
                this.h1 = 4023233417,
                this.h2 = 2562383102,
                this.h3 = 271733878,
                this.h4 = 3285377520,
                this.block = this.start = this.bytes = this.hBytes = 0,
                this.finalized = this.hashed = !1,
                this.first = !0
            }
            var t, n, i;
            return t = e,
            (n = [{
                key: "update",
                value: function(t) {
                    if (!this.finalized) {
                        for (var n, r = 0, i = (t = new Uint8Array(t)).length || 0, o = this.blocks; r < i; ) {
                            for (this.hashed && (this.hashed = !1,
                            o[0] = this.block,
                            o[16] = o[1] = o[2] = o[3] = o[4] = o[5] = o[6] = o[7] = o[8] = o[9] = o[10] = o[11] = o[12] = o[13] = o[14] = o[15] = 0),
                            n = this.start; r < i && n < 64; ++r)
                                o[n >> 2] |= t[r] << e.SHIFT[3 & n++];
                            this.lastByteIndex = n,
                            this.bytes += n - this.start,
                            n >= 64 ? (this.block = o[16],
                            this.start = n - 64,
                            this.hash(),
                            this.hashed = !0) : this.start = n
                        }
                        return this.bytes > 4294967295 && (this.hBytes += this.bytes / 4294967296 << 0,
                        this.bytes = this.bytes % 4294967296),
                        this
                    }
                }
            }, {
                key: "finalize",
                value: function() {
                    if (!this.finalized) {
                        this.finalized = !0;
                        var t = this.blocks
                          , n = this.lastByteIndex;
                        t[16] = this.block,
                        t[n >> 2] |= e.EXTRA[3 & n],
                        this.block = t[16],
                        n >= 56 && (this.hashed || this.hash(),
                        t[0] = this.block,
                        t[16] = t[1] = t[2] = t[3] = t[4] = t[5] = t[6] = t[7] = t[8] = t[9] = t[10] = t[11] = t[12] = t[13] = t[14] = t[15] = 0),
                        t[14] = this.hBytes << 3 | this.bytes >>> 29,
                        t[15] = this.bytes << 3,
                        this.hash()
                    }
                }
            }, {
                key: "hash",
                value: function() {
                    var e, t, n = this.h0, r = this.h1, i = this.h2, o = this.h3, a = this.h4, s = this.blocks;
                    for (e = 16; e < 80; ++e)
                        t = s[e - 3] ^ s[e - 8] ^ s[e - 14] ^ s[e - 16],
                        s[e] = t << 1 | t >>> 31;
                    for (e = 0; e < 20; e += 5)
                        n = (t = (r = (t = (i = (t = (o = (t = (a = (t = n << 5 | n >>> 27) + (r & i | ~r & o) + a + 1518500249 + s[e] << 0) << 5 | a >>> 27) + (n & (r = r << 30 | r >>> 2) | ~n & i) + o + 1518500249 + s[e + 1] << 0) << 5 | o >>> 27) + (a & (n = n << 30 | n >>> 2) | ~a & r) + i + 1518500249 + s[e + 2] << 0) << 5 | i >>> 27) + (o & (a = a << 30 | a >>> 2) | ~o & n) + r + 1518500249 + s[e + 3] << 0) << 5 | r >>> 27) + (i & (o = o << 30 | o >>> 2) | ~i & a) + n + 1518500249 + s[e + 4] << 0,
                        i = i << 30 | i >>> 2;
                    for (; e < 40; e += 5)
                        n = (t = (r = (t = (i = (t = (o = (t = (a = (t = n << 5 | n >>> 27) + (r ^ i ^ o) + a + 1859775393 + s[e] << 0) << 5 | a >>> 27) + (n ^ (r = r << 30 | r >>> 2) ^ i) + o + 1859775393 + s[e + 1] << 0) << 5 | o >>> 27) + (a ^ (n = n << 30 | n >>> 2) ^ r) + i + 1859775393 + s[e + 2] << 0) << 5 | i >>> 27) + (o ^ (a = a << 30 | a >>> 2) ^ n) + r + 1859775393 + s[e + 3] << 0) << 5 | r >>> 27) + (i ^ (o = o << 30 | o >>> 2) ^ a) + n + 1859775393 + s[e + 4] << 0,
                        i = i << 30 | i >>> 2;
                    for (; e < 60; e += 5)
                        n = (t = (r = (t = (i = (t = (o = (t = (a = (t = n << 5 | n >>> 27) + (r & i | r & o | i & o) + a - 1894007588 + s[e] << 0) << 5 | a >>> 27) + (n & (r = r << 30 | r >>> 2) | n & i | r & i) + o - 1894007588 + s[e + 1] << 0) << 5 | o >>> 27) + (a & (n = n << 30 | n >>> 2) | a & r | n & r) + i - 1894007588 + s[e + 2] << 0) << 5 | i >>> 27) + (o & (a = a << 30 | a >>> 2) | o & n | a & n) + r - 1894007588 + s[e + 3] << 0) << 5 | r >>> 27) + (i & (o = o << 30 | o >>> 2) | i & a | o & a) + n - 1894007588 + s[e + 4] << 0,
                        i = i << 30 | i >>> 2;
                    for (; e < 80; e += 5)
                        n = (t = (r = (t = (i = (t = (o = (t = (a = (t = n << 5 | n >>> 27) + (r ^ i ^ o) + a - 899497514 + s[e] << 0) << 5 | a >>> 27) + (n ^ (r = r << 30 | r >>> 2) ^ i) + o - 899497514 + s[e + 1] << 0) << 5 | o >>> 27) + (a ^ (n = n << 30 | n >>> 2) ^ r) + i - 899497514 + s[e + 2] << 0) << 5 | i >>> 27) + (o ^ (a = a << 30 | a >>> 2) ^ n) + r - 899497514 + s[e + 3] << 0) << 5 | r >>> 27) + (i ^ (o = o << 30 | o >>> 2) ^ a) + n - 899497514 + s[e + 4] << 0,
                        i = i << 30 | i >>> 2;
                    this.h0 = this.h0 + n << 0,
                    this.h1 = this.h1 + r << 0,
                    this.h2 = this.h2 + i << 0,
                    this.h3 = this.h3 + o << 0,
                    this.h4 = this.h4 + a << 0
                }
            }, {
                key: "digest",
                value: function() {
                    this.finalize();
                    var e = this.h0
                      , t = this.h1
                      , n = this.h2
                      , r = this.h3
                      , i = this.h4;
                    return [e >> 24 & 255, e >> 16 & 255, e >> 8 & 255, 255 & e, t >> 24 & 255, t >> 16 & 255, t >> 8 & 255, 255 & t, n >> 24 & 255, n >> 16 & 255, n >> 8 & 255, 255 & n, r >> 24 & 255, r >> 16 & 255, r >> 8 & 255, 255 & r, i >> 24 & 255, i >> 16 & 255, i >> 8 & 255, 255 & i]
                }
            }]) && r(t.prototype, n),
            i && r(t, i),
            e
        }();
        n.default = o,
        i(o, "EXTRA", [-2147483648, 8388608, 32768, 128]),
        i(o, "SHIFT", [24, 16, 8, 0])
    }
    , {}],
    24: [function(e, t, n) {
        "use strict";
        function r(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        function i(e, t, n) {
            return t in e ? Object.defineProperty(e, t, {
                value: n,
                enumerable: !0,
                configurable: !0,
                writable: !0
            }) : e[t] = n,
            e
        }
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var o = function() {
            function e() {
                !function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, e),
                this.blocks = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                this.h0 = 1779033703,
                this.h1 = 3144134277,
                this.h2 = 1013904242,
                this.h3 = 2773480762,
                this.h4 = 1359893119,
                this.h5 = 2600822924,
                this.h6 = 528734635,
                this.h7 = 1541459225,
                this.block = this.start = this.bytes = this.hBytes = 0,
                this.finalized = this.hashed = !1,
                this.first = !0
            }
            var t, n, i;
            return t = e,
            (n = [{
                key: "update",
                value: function(t) {
                    if (!this.finalized) {
                        for (var n, r = 0, i = (t = new Uint8Array(t)).length, o = this.blocks; r < i; ) {
                            for (this.hashed && (this.hashed = !1,
                            o[0] = this.block,
                            o[16] = o[1] = o[2] = o[3] = o[4] = o[5] = o[6] = o[7] = o[8] = o[9] = o[10] = o[11] = o[12] = o[13] = o[14] = o[15] = 0),
                            n = this.start; r < i && n < 64; ++r)
                                o[n >> 2] |= t[r] << e.SHIFT[3 & n++];
                            this.lastByteIndex = n,
                            this.bytes += n - this.start,
                            n >= 64 ? (this.block = o[16],
                            this.start = n - 64,
                            this.hash(),
                            this.hashed = !0) : this.start = n
                        }
                        return this.bytes > 4294967295 && (this.hBytes += this.bytes / 4294967296 << 0,
                        this.bytes = this.bytes % 4294967296),
                        this
                    }
                }
            }, {
                key: "finalize",
                value: function() {
                    if (!this.finalized) {
                        this.finalized = !0;
                        var t = this.blocks
                          , n = this.lastByteIndex;
                        t[16] = this.block,
                        t[n >> 2] |= e.EXTRA[3 & n],
                        this.block = t[16],
                        n >= 56 && (this.hashed || this.hash(),
                        t[0] = this.block,
                        t[16] = t[1] = t[2] = t[3] = t[4] = t[5] = t[6] = t[7] = t[8] = t[9] = t[10] = t[11] = t[12] = t[13] = t[14] = t[15] = 0),
                        t[14] = this.hBytes << 3 | this.bytes >>> 29,
                        t[15] = this.bytes << 3,
                        this.hash()
                    }
                }
            }, {
                key: "hash",
                value: function() {
                    var t, n, r, i, o, a, s, u, l, c = this.h0, f = this.h1, d = this.h2, h = this.h3, b = this.h4, v = this.h5, m = this.h6, p = this.h7, y = this.blocks;
                    for (t = 16; t < 64; ++t)
                        n = ((o = y[t - 15]) >>> 7 | o << 25) ^ (o >>> 18 | o << 14) ^ o >>> 3,
                        r = ((o = y[t - 2]) >>> 17 | o << 15) ^ (o >>> 19 | o << 13) ^ o >>> 10,
                        y[t] = y[t - 16] + n + y[t - 7] + r << 0;
                    for (l = f & d,
                    t = 0; t < 64; t += 4)
                        this.first ? (a = 704751109,
                        p = (o = y[0] - 210244248) - 1521486534 << 0,
                        h = o + 143694565 << 0,
                        this.first = !1) : (n = (c >>> 2 | c << 30) ^ (c >>> 13 | c << 19) ^ (c >>> 22 | c << 10),
                        i = (a = c & f) ^ c & d ^ l,
                        p = h + (o = p + (r = (b >>> 6 | b << 26) ^ (b >>> 11 | b << 21) ^ (b >>> 25 | b << 7)) + (b & v ^ ~b & m) + e.K[t] + y[t]) << 0,
                        h = o + (n + i) << 0),
                        n = (h >>> 2 | h << 30) ^ (h >>> 13 | h << 19) ^ (h >>> 22 | h << 10),
                        i = (s = h & c) ^ h & f ^ a,
                        m = d + (o = m + (r = (p >>> 6 | p << 26) ^ (p >>> 11 | p << 21) ^ (p >>> 25 | p << 7)) + (p & b ^ ~p & v) + e.K[t + 1] + y[t + 1]) << 0,
                        n = ((d = o + (n + i) << 0) >>> 2 | d << 30) ^ (d >>> 13 | d << 19) ^ (d >>> 22 | d << 10),
                        i = (u = d & h) ^ d & c ^ s,
                        v = f + (o = v + (r = (m >>> 6 | m << 26) ^ (m >>> 11 | m << 21) ^ (m >>> 25 | m << 7)) + (m & p ^ ~m & b) + e.K[t + 2] + y[t + 2]) << 0,
                        n = ((f = o + (n + i) << 0) >>> 2 | f << 30) ^ (f >>> 13 | f << 19) ^ (f >>> 22 | f << 10),
                        i = (l = f & d) ^ f & h ^ u,
                        b = c + (o = b + (r = (v >>> 6 | v << 26) ^ (v >>> 11 | v << 21) ^ (v >>> 25 | v << 7)) + (v & m ^ ~v & p) + e.K[t + 3] + y[t + 3]) << 0,
                        c = o + (n + i) << 0;
                    this.h0 = this.h0 + c << 0,
                    this.h1 = this.h1 + f << 0,
                    this.h2 = this.h2 + d << 0,
                    this.h3 = this.h3 + h << 0,
                    this.h4 = this.h4 + b << 0,
                    this.h5 = this.h5 + v << 0,
                    this.h6 = this.h6 + m << 0,
                    this.h7 = this.h7 + p << 0
                }
            }, {
                key: "digest",
                value: function() {
                    this.finalize();
                    var e = this.h0
                      , t = this.h1
                      , n = this.h2
                      , r = this.h3
                      , i = this.h4
                      , o = this.h5
                      , a = this.h6
                      , s = this.h7
                      , u = [e >> 24 & 255, e >> 16 & 255, e >> 8 & 255, 255 & e, t >> 24 & 255, t >> 16 & 255, t >> 8 & 255, 255 & t, n >> 24 & 255, n >> 16 & 255, n >> 8 & 255, 255 & n, r >> 24 & 255, r >> 16 & 255, r >> 8 & 255, 255 & r, i >> 24 & 255, i >> 16 & 255, i >> 8 & 255, 255 & i, o >> 24 & 255, o >> 16 & 255, o >> 8 & 255, 255 & o, a >> 24 & 255, a >> 16 & 255, a >> 8 & 255, 255 & a];
                    return u.push(s >> 24 & 255, s >> 16 & 255, s >> 8 & 255, 255 & s),
                    u
                }
            }]) && r(t.prototype, n),
            i && r(t, i),
            e
        }();
        n.default = o,
        i(o, "EXTRA", [-2147483648, 8388608, 32768, 128]),
        i(o, "SHIFT", [24, 16, 8, 0]),
        i(o, "K", [1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298])
    }
    , {}],
    25: [function(e, t, n) {
        "use strict";
        function r(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var i = function() {
            function e() {
                !function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, e)
            }
            var t, n, i;
            return t = e,
            i = [{
                key: "toHex",
                value: function(e) {
                    return e ? Array.from(e, (function(e) {
                        return ("0" + (255 & e).toString(16)).slice(-2)
                    }
                    )).join(" ") : null
                }
            }],
            (n = null) && r(t.prototype, n),
            i && r(t, i),
            e
        }();
        n.default = i
    }
    , {}],
    26: [function(e, t, n) {
        "use strict";
        function r(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var i = function() {
            function e() {
                !function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, e)
            }
            var t, n, i;
            return t = e,
            i = [{
                key: "generate",
                value: function(t, n) {
                    t.empty(),
                    t.removeClass("d-none");
                    var r = $('<div id="accordion">');
                    t.append(r),
                    n.forEach((function(t, n) {
                        return e.createCard(r, t, n)
                    }
                    ))
                }
            }, {
                key: "createCard",
                value: function(t, n, r) {
                    var i = $('<div class="card">');
                    t.append(i);
                    var o = $('<div class="card-header" id="heading' + r + '">');
                    i.append(o);
                    var a = $("<span>");
                    o.append(a);
                    var s = $('<button class="btn btn-link" data-toggle="collapse" data-target="#collapse' + r + '" aria-expanded="' + (0 === r ? "true" : "false") + '" aria-controls="collapse' + r + '">');
                    s.text(n.subject.commonName ? n.subject.commonName : "Certificate " + r),
                    a.append(s);
                    var u = $('<div id="collapse' + r + '" class="collapse ' + (0 === r ? "show" : "hide") + '" aria-labelledby="heading' + r + '" data-parent="#accordion">');
                    i.append(u);
                    var l = $('<div class="card-body">');
                    u.append(l);
                    var c = $('<ul class="nav nav-tabs" role="tablist">');
                    l.append(c);

/*                    
                    var f = $('<li class="nav-item">');
                    c.append(f);

                    var d = $('<a class="nav-link active" id="basic-tab' + r + '" data-toggle="tab" href="#basic' + r + '" role="tab" aria-controls="basic" aria-selected="true">Basic</a>');
                    f.append(d);
                    
                    var h = $('<li class="nav-item">');
                    c.append(h);
                    var b = $('<a class="nav-link" id="details-tab' + r + '" data-toggle="tab" href="#details' + r + '" role="tab" aria-controls="details" aria-selected="true">Details</a>');
                    h.append(b);

*/                    
                    
                    var v = $('<div class="tab-content pt-3" style="height: 423px;">');
                    l.append(v);
                    var m = $('<div class="tab-pane fade show active" id="basic' + r + '" role="tabpanel" aria-labelledby="basic-tab' + r + '">');
                    e.addBasicContent(m, n),
                    v.append(m);
/*                    
                    var p = $('<div class="tab-pane fade" id="details' + r + '" role="tabpanel" aria-labelledby="details-tab' + r + '">');
                    e.addDetailsContent(p, n),
                    v.append(p)
*/

                    
                }
            }, {
                key: "addBasicContent",
                value: function(t, n) {
                    var r = $('<ul style="height: 410px;overflow-y: auto;">');
                    t.append(r),
                    e.addBasicContentItem(r, "Issued  To", n.subject),
                    e.addBasicContentItem(r, "Issued By", n.issuer),
                    e.addBasicContentItem(r, "Serial Number", n.serialNumber),
                    e.addBasicContentItem(r, "Issued On", n.notBefore),
                    e.addBasicContentItem(r, "Expires On", n.notAfter),
                    e.addBasicContentItem(r, "SHA-256 Fingerprint", n.sha256FingerPrint),
                    e.addBasicContentItem(r, "SHA-1 Fingerprint", n.sha1FingerPrint)
                }
            }, {

                key: "addBasicContentItem",
                value: function(e, t, n) {
                    var r = $("<li>");
                    e.append(r);
                    var i = $("<span>");
                    i.text(t + ": ");
                    var o = $("<span>");
                    o.text(n),
                    r.append(i, o)
                    
                }
            }, {
                key: "addDetailsContent",
                value: function(t, n) {
                    var r = $('<ul class="details-list" style="height: 300px; overflow-y: scroll;">');
                    t.append(r),
                    e.addDetailsContentItem(r, "Version", n.version),
                    e.addDetailsContentItem(r, "Serial Number", n.serialNumber),
                    e.addDetailsContentItem(r, "Signature Algorithm", n.signatureAlgorithm),
                    e.addDetailsContentItem(r, "Issuer", n.issuer);
                    var i = $("<li>");
                    i.text("Validity Period"),
                    r.append(i);
                    var o = $("<ul>");
                    i.append(o),
                    e.addDetailsContentItem(o, "Not Before", n.notBefore),
                    e.addDetailsContentItem(o, "Not After", n.notAfter),
                    e.addDetailsContentItem(r, "Subject", n.subject);
                    var a = $("<li>");
                    a.text("Subject Public Key Info"),
                    r.append(a);
                    var s = $("<ul>");
                    if (a.append(s),
                    e.addDetailsContentItem(s, "Subject Public Key Algorithm", n.subjectPublicKeyAlgorithm),
                    e.addDetailsContentItem(s, "Subject Public Key", n.subjectPublicKey),
                    n.issuerUniqueId && e.addDetailsContentItem(r, "Issuer Unique ID", n.issuerUniqueId),
                    n.subjectUniqueId && e.addDetailsContentItem(r, "Subject Unique ID", n.subjectUniqueId),
                    n.extensions) {
                        var u = $("<li>");
                        u.text("Extensions"),
                        r.append(u);
                        var l = $("<ul>");
                        u.append(l),
                        n.extensions.forEach((function(t) {
                            var n = "Critical: " + (t.critical ? "Yes" : "No") + "\r\n" + t.value;
                            e.addDetailsContentItem(l, t.name, n)
                        }
                        ))
                    }
                    e.addDetailsContentItem(r, "Certificate Signature Algorithm", n.certificateSignatureAlgorithm),
                    e.addDetailsContentItem(r, "Certificate Signature", n.certificateSignatureValue),
                    e.addDetailsContentItem(r, "SHA-256 Fingerprint", n.sha256FingerPrint),
                    e.addDetailsContentItem(r, "SHA-1 Fingerprint", n.sha1FingerPrint);
                    var c = $('<textarea rows="4" wrap="hard" class="form-control w-100 result-value" readonly>Select an item from the list above to display its value.</textarea>');
                    t.append(c),
                    r.find("li.details").click((function(e) {
                        var t = $(e.target);
                        t.parents(".details-list").find("li").removeClass("selected"),
                        t.addClass("selected"),
                        c.val(t.data("val"))
                    }
                    ))
                }
            }, {
                key: "addDetailsContentItem",
                value: function(e, t, n) {
                    var r = $('<li class="details">');
                    r.text(t),
                    r.data("val", n),
                    e.append(r)
                }
            }],
            (n = null) && r(t.prototype, n),
            i && r(t, i),
            e
        }();
        n.default = i
    }
    , {}],
    27: [function(e, t, n) {
        "use strict";
        t.exports = function() {
            return {
                track: function(e) {
                    _dev ? console.log("Share: " + e) : gtag("event", "share", {
                        event_category: "Share",
                        event_label: e
                    })
                }
            }
        }
    }
    , {}],
    28: [function(e, t, n) {
        "use strict";
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var r, i = (r = e("./hex")) && r.__esModule ? r : {
            default: r
        };
        function o(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        var a = function() {
            function e() {
                !function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, e),
                this.modulus = null,
                this.exponent = null
            }
            var t, n, r;
            return t = e,
            r = [{
                key: "fromElement",
                value: function(t) {
                    var n = new e;
                    t.readAsConstructed(!0);
                    var r = t.elements[0];
                    if (!r || !r.tag.isEqualTo({
                        class: 0,
                        constructed: !0,
                        number: 16
                    }))
                        throw new Error("Could not find public key sequence.");
                    var o = r.elements[0];
                    if (!o || !o.tag.isEqualTo({
                        class: 0,
                        constructed: !1,
                        number: 2
                    }))
                        throw new Error("Could not find public key modulus.");
                    var a = o.content;
                    a.length > 0 && 0 === a[0] && (a = a.slice(1, a.length)),
                    n.modulus = i.default.toHex(a);
                    var s = r.elements[1];
                    if (!s || !s.tag.isEqualTo({
                        class: 0,
                        constructed: !1,
                        number: 2
                    }))
                        throw new Error("Could not find public key exponent.");
                    return n.exponent = i.default.toHex(s.content),
                    n
                }
            }],
            (n = [{
                key: "toString",
                value: function() {
                    return "Modulus: " + this.modulus + "\r\nExponent: " + this.exponent
                }
            }]) && o(t.prototype, n),
            r && o(t, r),
            e
        }();
        n.default = a
    }
    , {
        "./hex": 25
    }],
    29: [function(e, t, n) {
        "use strict";
        Object.defineProperty(n, "__esModule", {
            value: !0
        }),
        n.default = void 0;
        var r, i = (r = e("./hex")) && r.__esModule ? r : {
            default: r
        };
        function o(e, t) {
            for (var n = 0; n < t.length; n++) {
                var r = t[n];
                r.enumerable = r.enumerable || !1,
                r.configurable = !0,
                "value"in r && (r.writable = !0),
                Object.defineProperty(e, r.key, r)
            }
        }
        var a = function() {
            function e() {
                !function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, e),
                this.publicKey = null
            }
            var t, n, r;
            return t = e,
            r = [{
                key: "fromElement",
                value: function(t) {
                    var n = new e
                      , r = t.content;
                    return r.length > 0 && 0 === r[0] && (r = r.slice(1, r.length)),
                    n.publicKey = i.default.toHex(r),
                    n
                }
            }],
            (n = [{
                key: "toString",
                value: function() {
                    return this.publicKey
                }
            }]) && o(t.prototype, n),
            r && o(t, r),
            e
        }();
        n.default = a
    }
    , {
        "./hex": 25
    }]
}, {}, [15]);
