import { isError, Result } from './result';

interface URL {
  Scheme?: string;
  Opaque?: string; // encoded opaque data
  Host?: string; // host or host:port
  Path?: string; // path (relative paths may omit leading slash)
  RawPath?: string; // encoded path hint (see EscapedPath method)
  OmitHost?: boolean; // do not emit empty host (authority)
  ForceQuery?: boolean; // append a query ('?') even if RawQuery is empty
  RawQuery?: string; // encoded query values, without '?'
  Fragment?: string; // fragment for references, without '#'
  RawFragment?: string; // encoded fragment hint (see EscapedFragment method)
}

interface Scheme {
    Scheme: string;
    Path: string;
}

declare namespace strings {
    const cut = (s:string, sep: string) : {before:string , after: string, found: boolean} => {
        var i = s.indexOf(sep);
        if (i >= 0) {
            return { 
                before: s.slice(0, i), 
                after: s.slice(i+sep.length), 
                found: true
            }
        }
        return {
            before: s, 
            after: "", 
            found: false
        }
    }

    const count = (s: string, c: string): number => {
        return s.split(c).length - 1;
    }

    const hasPrefix = (s: string, prefix: string): boolean => {
        return s.length >= prefix.length && s.slice(0, prefix.length) === prefix
    }
    
    const hasSuffix = (s: string, suffix: string): boolean => {
        return s.length >= suffix.length && s.slice(s.length-suffix.length) === prefix
    }
}

// stringContainsCTLByte reports whether s contains any ASCII control character.
var stringContainsCTLByte = (s: string): boolean => {
    let i = 0;
	while (i < s.length) {
		var b = s.charCodeAt(i);
		if (b < 0x20 || b == 0x7f) {
			return true;
		}
        i++;
	}
	return false;
}

// Maybe rawURL is of the form scheme:path.
// (Scheme must be [a-zA-Z][a-zA-Z0-9+.-]*)
// If so, return scheme, path; else return "", rawURL.
var getScheme = (rawURL: string): Result<Scheme> => {
    let i = 0;
	while (i < rawURL.length) {
		var c = rawURL.charCodeAt(i);
		if(!('a'.charCodeAt(0) <= c && c <= 'z'.charCodeAt(0) || 'A'.charCodeAt(0) <= c && c <= 'Z'.charCodeAt(0))) {
            if('0'.charCodeAt(0) <= c && c <= '9'.charCodeAt(0) || c == '+'.charCodeAt(0) || c == '-'.charCodeAt(0) || c == '.'.charCodeAt(0)) {
                if (i == 0) {
                    return { Scheme: "", Path: rawURL }
                }
            }
        } else if (rawURL[i] == ':') {
			if (i == 0) {
                return { name: "MISSING_SCHEME", message: "missing protocol scheme"}
			}
            return { Scheme: rawURL.slice(0, i), Path: rawURL.slice(i+1) }
        } else {
			// we have encountered an invalid character,
			// so there is no valid scheme
			return { Scheme: "", Path: rawURL}
		}
        i++;
    }
	return { Scheme: "", Path: rawURL }
}

// validOptionalPort reports whether port is either an empty string
// or matches /^:\d*$/
var validOptionalPort = (port: string): boolean {
	if (port == "") {
		return true
	}

	if (port[0] != ':') {
		return false
	}

	for (var b = 1; b < port.length; b++) {
		if (port.charCodeAt(b) < '0'.charCodeAt(0) || port.charCodeAt(b) > '9'.charCodeAt(0)) {
			return false
		}
	}
	return true
}


var ishex = (c: string): boolean => {
	let v = c.charCodeAt(0);
	if (v >= '0'.charCodeAt(0) && v <= '9'.charCodeAt(0)) {
		return true;
	}
	if (v >= 'a'.charCodeAt(0) && v <= 'f'.charCodeAt(0)) {
		return true;
	}
	if (v >= 'A'.charCodeAt(0) && v <= 'F'.charCodeAt(0)) {
		return true;
	}
	return false;
}

var unhex = (c: string): number {
	let v = c.charCodeAt(0);
	if (v >= '0'.charCodeAt(0) && v <= '9'.charCodeAt(0)) {
		return v - '0'.charCodeAt(0);
	}
	if (v >= 'a'.charCodeAt(0) && v <= 'f'.charCodeAt(0)) {
		return v - 'a'.charCodeAt(0) + 10;
	}
	if (v >= 'A'.charCodeAt(0) && v <= 'F'.charCodeAt(0)) {
		return v - 'A'.charCodeAt(0) + 10;
	}
	return 0;
}


// unescape unescapes a string; the mode specifies
// which section of the URL string is being unescaped.
var unescape = (s: string, mode: number): Result<string> => {
	// Count %, check that they're well-formed.
	var n = 0;
	var hasPlus = false;
	var i = 0;
	while (i < s.length){
		switch s[i] {
		case '%':
			n++
			if (i+2 >= s.length || !ishex(s[i+1]) || !ishex(s[i+2])) {
				s = s.slice(i)
				if (s.length > 3) {
					s = s.slice(0, 3)
				}
				return { name: "", message: s }
			}
			// Per https://tools.ietf.org/html/rfc3986#page-21
			// in the host component %-encoding can only be used
			// for non-ASCII bytes.
			// But https://tools.ietf.org/html/rfc6874#section-2
			// introduces %25 being allowed to escape a percent sign
			// in IPv6 scoped-address literals. Yay.
			if (mode == encodeHost && unhex(s[i+1]) < 8 && s.slice(i, i+3) != "%25") {
				return { name: "", message: s.slice(i, i+3) }
			}
			if (mode == encodeZone) {
				// RFC 6874 says basically "anything goes" for zone identifiers
				// and that even non-ASCII can be redundantly escaped,
				// but it seems prudent to restrict %-escaped bytes here to those
				// that are valid host name bytes in their unescaped form.
				// That is, you can use escaping in the zone identifier but not
				// to introduce bytes you couldn't just write directly.
				// But Windows puts spaces here! Yay.
				let v = unhex(s[i+1])<<4 | unhex(s[i+2]);
				if (s.slice(i, i+3) != "%25" && v != ' '.charCodeAt(0) && shouldEscape(v, encodeHost)) {
					return { name: "", message: s.slice(i, i+3) }
				}
			}
			i += 3
		case '+':
			hasPlus = mode == encodeQueryComponent
			i++
		default:
			if ((mode == encodeHost || mode == encodeZone) && s[i] < 0x80 && shouldEscape(s[i], mode)) {
				return "", InvalidHostError(s[i : i+1])
			}
			i++
		}
	}

	if (n == 0 && !hasPlus) {
		return s, nil
	}

	t = "";
	for (var i =0; i < s.length; i++) {
		switch s[i] {
		case '%':
			t.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
		case '+':
			if mode == encodeQueryComponent {
				t.WriteByte(' ')
			} else {
				t.WriteByte('+')
			}
		default:
			t.WriteByte(s[i])
		}
	}
	return t.String(), nil
}

// parseHost parses host as an authority without user
// information. That is, as host[:port].
var parseHost = (host: string): Result<string> {
	if (strings.hasPrefix(host, "[")) {
		// Parse an IP-Literal in RFC 3986 and RFC 6874.
		// E.g., "[fe80::1]", "[fe80::1%25en0]", "[fe80::1]:80".
		var i = host.lastIndexOf("]")
		if (i < 0) {
			return { name: 'MISSING_RBRACKET_IN_HOST', message: "missing ']' in host" }
		}

		var colonPort = host.slice(i+1)
		if (!validOptionalPort(colonPort)) {
			return { name: 'INVALID_HOST_PORT', message: `invalid port ${colonPort} after host`}
		}

		// RFC 6874 defines that %25 (%-encoded percent) introduces
		// the zone identifier, and the zone identifier can use basically
		// any %-encoding it likes. That's different from the host, which
		// can only %-encode non-ASCII bytes.
		// We do impose some restrictions on the zone, to avoid stupidity
		// like newlines.
		var zone = host.slice(0, i).indexOf("%25");
		if (zone >= 0) {
			host1, err := unescape(host[:zone], encodeHost)
			if err != nil {
				return "", err
			}
			host2, err := unescape(host[zone:i], encodeZone)
			if err != nil {
				return "", err
			}
			host3, err := unescape(host[i:], encodeHost)
			if err != nil {
				return "", err
			}
			return host1 + host2 + host3, nil
		}
	} else if (i := strings.LastIndex(host, ":"); i != -1) {
		colonPort := host[i:]
		if !validOptionalPort(colonPort) {
			return "", fmt.Errorf("invalid port %q after host", colonPort)
		}
	}

	var err error
	if host, err = unescape(host, encodeHost); err != nil {
		return "", err
	}
	return host, nil
}


var parseAuthority = (authority: string):{} => {
	var i = authority.lastIndexOf("@");
	if (i < 0) {
		host, err = parseHost(authority)
	} else {
		host, err = parseHost(authority[i+1:])
	}
	if err != nil {
		return nil, "", err
	}
	if i < 0 {
		return nil, host, nil
	}
	userinfo := authority[:i]
	if !validUserinfo(userinfo) {
		return nil, "", errors.New("net/url: invalid userinfo")
	}
	if !strings.Contains(userinfo, ":") {
		if userinfo, err = unescape(userinfo, encodeUserPassword); err != nil {
			return nil, "", err
		}
		user = User(userinfo)
	} else {
		username, password, _ := strings.Cut(userinfo, ":")
		if username, err = unescape(username, encodeUserPassword); err != nil {
			return nil, "", err
		}
		if password, err = unescape(password, encodeUserPassword); err != nil {
			return nil, "", err
		}
		user = UserPassword(username, password)
	}
	return user, host, nil
}

// parse parses a URL from a string in one of two contexts. If
// viaRequest is true, the URL is assumed to have arrived via an HTTP request,
// in which case only absolute URLs or path-absolute relative URLs are allowed.
// If viaRequest is false, all forms of relative URLs are allowed.
var parse = (rawURL: string, viaRequest: boolean): Result<URL> => {
	if (stringContainsCTLByte(rawURL)) {
        return { name: "INVALID_CTRL_CHARACTER", message: "invalid control character in URL"}
	}

	if (rawURL == "" && viaRequest) {
        return { name: "EMPTY_URL", message: "empty url"}
	}

	var url: URL = {};

	if (rawURL == "*") {
		url.Path = "*";
		return url
	}

	// Split off possible leading "http:", "mailto:", etc.
	// Cannot contain escaped characters.
    var decodedScheme = getScheme(rawURL);
	if (isError(decodedScheme)) {
        return decodedScheme
	}
    url.Scheme = decodedScheme.Scheme
    let rest = decodedScheme.Path

	url.Scheme = url.Scheme.toLowerCase()

	if (rest.endsWith("?") && strings.count(rest, "?") == 1) {
		url.ForceQuery = true
		rest = rest.slice(0, rest.length-1)
	} else {
		var cutRes = strings.cut(rest, "?")
        rest = cutRes.before
        url.RawQuery = cutRes.after
	}

	if (!(rest.length > 0 && rest[0] == "/")) {
		if (url.Scheme != "") {
			// We consider rootless paths per RFC 3986 as opaque.
			url.Opaque = rest
			return url
		}
		if (viaRequest) {
            return { name: "INVALID_REQUEST_URI", message: "invalid URI for request" }
		}

		// Avoid confusion with malformed schemes, like cache_object:foo/bar.
		// See golang.org/issue/16822.
		//
		// RFC 3986, §3.3:
		// In addition, a URI reference (Section 4.1) may be a relative-path reference,
		// in which case the first path segment cannot contain a colon (":") character.
		var cutRes = strings.cut(rest, "/")
		if (cutRes.before.indexOf(":") !== -1) {
            return { name: "PATH_UNEXPECTED_COLON", message: "first path segment in URL cannot contain colon" }
		}
	}

	if ((url.Scheme != "" || !viaRequest && !strings.hasPrefix(rest, "///")) && strings.hasPrefix(rest, "//")) {
		var authority: string = rest.slice(2)
        rest = ""
        let i = authority.indexOf("/");
		if (i >= 0) {
            let tup = [authority.slice(0,i), authority.slice(i)];
            authority = tup[0];
            rest = tup[1];
		}
        //url.User, url.Host, err = parseAuthority(authority)
		let authorityRes = parseAuthority(authority)
		if (isError(authorityRes)) {
            return authorityRes
		}
	} else if (url.Scheme != "" && strings.hasPrefix(rest, "/")) {
		// OmitHost is set to true when rawURL has an empty host (authority).
		// See golang.org/issue/46059.
		url.OmitHost = true
	}

	// Set Path and, optionally, RawPath.
	// RawPath is a hint of the encoding of Path. We don't want to set it if
	// the default escaping of Path is equivalent, to help make sure that people
	// don't rely on it in general.
	if err := url.setPath(rest); err != nil {
		return nil, err
	}
	return url, nil
}


// Parse parses a raw url into a URL structure.
//
// The url may be relative (a path, without a host) or absolute
// (starting with a scheme). Trying to parse a hostname and path
// without a scheme is invalid but may not necessarily return an
// error, due to parsing ambiguities.
export const Parse = (rawURL: string): Result<URL> => {
    // Cut off #frag
	let cutRes = strings.Cut(rawURL, "#");
	url, err := parse(cutRes.before, false)
	if err != nil {
		return nil, &Error{"parse", u, err}
	}
	if frag == "" {
		return url, nil
	}
	if err = url.setFragment(frag); err != nil {
		return nil, &Error{"parse", rawURL, err}
	}
	return url, nil
    return nil
}