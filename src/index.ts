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
		url.User, url.Host, err = parseAuthority(authority)
		if err != nil {
			return nil, err
		}
	} else if url.Scheme != "" && strings.HasPrefix(rest, "/") {
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