package protocol

import "strings"

// IfNoneMatch reports whether an If-None-Match field names the entity-tag
// etag, as RFC 9110 §13.1.2 has a server evaluate it: a value of "*" names
// any page, and a list of entity-tags names a page whose tag is one of them
// by the weak comparison (§8.8.3.2). Each tag of the list is read through its
// closing quote (cutETag), since a comma and a "*" are characters a tag may
// hold, and empty elements are taken (§5.6.1.2). A value of any other form,
// "*" among tags included, names nothing: the condition is true, and the page
// is answered in full. lines are the field's lines as a request carries them
// (http.Header.Values), read as one list (§5.3).
func IfNoneMatch(lines []string, etag string) bool {
	v := strings.Trim(strings.Join(lines, ","), " \t")
	if v == "*" {
		return true
	}
	named := false
	for v != "" {
		if v[0] == ',' {
			v = strings.TrimLeft(v[1:], " \t")
			continue
		}
		tag, rest, ok := cutETag(v)
		if !ok {
			return false
		}
		named = named || strings.TrimPrefix(tag, "W/") == strings.TrimPrefix(etag, "W/")
		if v = strings.TrimLeft(rest, " \t"); v != "" && v[0] != ',' {
			return false
		}
	}
	return named
}

// IfMatch reports whether an If-Match field's condition is true for a page
// whose entity-tag is etag, "" for a page that carries none, as RFC 9110
// §13.1.1 has an origin server evaluate it, and as PROTOCOL.md §5.1 reads
// it: no field is no condition; "*" as the whole value is true, a page with
// no tag included, since it is a current representation; a list of
// entity-tags, each read through its closing quote (cutETag) and empty
// elements taken (§5.6.1.2), is true when one of them is etag by the strong
// comparison (§8.8.3.2), which a weak tag never is; and a value of any other
// form is false: "*" among tags, a tag followed by anything but a comma, and
// an empty value, which lists no tag, among them. lines are the field's
// lines as a request carries them (http.Header.Values), read as one list
// (§5.3), as IfNoneMatch reads its field. net/http's checkIfMatch differs:
// it reads the first line alone, takes an empty one as no field, and is
// true at the first "*" or matching tag, whatever follows it.
func IfMatch(lines []string, etag string) bool {
	if len(lines) == 0 {
		return true
	}
	v := strings.Trim(strings.Join(lines, ","), " \t")
	if v == "*" {
		return true
	}
	matched := false
	for v != "" {
		if v[0] == ',' {
			v = strings.TrimLeft(v[1:], " \t")
			continue
		}
		tag, rest, ok := cutETag(v)
		if !ok {
			return false
		}
		matched = matched || etag != "" && tag == etag && !strings.HasPrefix(tag, "W/")
		if v = strings.TrimLeft(rest, " \t"); v != "" && v[0] != ',' {
			return false
		}
	}
	return matched
}

// cutETag cuts the entity-tag that s begins with, [W/] DQUOTE *etagc DQUOTE
// (RFC 9110 §8.8.3), from what follows it, as net/http's scanETag reads one.
func cutETag(s string) (tag, rest string, ok bool) {
	i := 0
	if strings.HasPrefix(s, "W/") {
		i = 2
	}
	if i >= len(s) || s[i] != '"' {
		return "", "", false
	}
	for j := i + 1; j < len(s); j++ {
		switch c := s[j]; {
		case c == '"':
			return s[:j+1], s[j+1:], true
		case c == 0x21 || c >= 0x23 && c <= 0x7e || c >= 0x80:
		default:
			return "", "", false
		}
	}
	return "", "", false
}
