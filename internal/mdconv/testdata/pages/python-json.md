---
title: json — JSON encoder and decoder
description: "Source code: Lib/json/__init__.py JSON (JavaScript Object Notation), specified by RFC 7159(which obsoletes RFC 4627) and by ECMA-404, is a lightweight data interchange format inspired by JavaScript..."
image: https://docs.python.org/3.15/_images/social_previews/summary_library_json_0fabf18f.png
---

# `json` — JSON encoder and decoder[¶](https://docs.python.org/3/library/json.html#module-json "Link to this heading")

**Source code:** [Lib/json/\_\_init\_\_.py](https://github.com/python/cpython/tree/3.15/Lib/json/__init__.py)

* * *

[JSON (JavaScript Object Notation)](https://json.org), specified by [**RFC 7159**](https://datatracker.ietf.org/doc/html/rfc7159.html) (which obsoletes [**RFC 4627**](https://datatracker.ietf.org/doc/html/rfc4627.html)) and by [ECMA-404](https://ecma-international.org/publications-and-standards/standards/ecma-404/), is a lightweight data interchange format inspired by [JavaScript](https://en.wikipedia.org/wiki/JavaScript) object literal syntax (although it is not a strict subset of JavaScript [\[1\]](https://docs.python.org/3/library/json.html#rfc-errata) ).

Note

The term “object” in the context of JSON processing in Python can be ambiguous. All values in Python are objects. In JSON, an object refers to any data wrapped in curly braces, similar to a Python dictionary.

Warning

Be cautious when parsing JSON data from untrusted sources. A malicious JSON string may cause the decoder to consume considerable CPU and memory resources. Limiting the size of data to be parsed is recommended.

This module exposes an API familiar to users of the standard library [`marshal`](https://docs.python.org/3/library/marshal.html#module-marshal "marshal: Convert Python objects to streams of bytes and back (with different constraints).") and [`pickle`](https://docs.python.org/3/library/pickle.html#module-pickle "pickle: Convert Python objects to streams of bytes and back.") modules.

Encoding basic Python object hierarchies:

```
>>> import json
>>> json.dumps(['foo', {'bar': ('baz', None, 1.0, 2)}])
'["foo", {"bar": ["baz", null, 1.0, 2]}]'
>>> print(json.dumps("\"foo\bar"))
"\"foo\bar"
>>> print(json.dumps('\u1234'))
"\u1234"
>>> print(json.dumps('\\'))
"\\"
>>> print(json.dumps({"c": 0, "b": 0, "a": 0}, sort_keys=True))
{"a": 0, "b": 0, "c": 0}
>>> from io import StringIO
>>> io = StringIO()
>>> json.dump(['streaming API'], io)
>>> io.getvalue()
'["streaming API"]'
```

Compact encoding:

```
>>> import json
>>> json.dumps([1, 2, 3, {'4': 5, '6': 7}], separators=(',', ':'))
'[1,2,3,{"4":5,"6":7}]'
```

Pretty printing:

```
>>> import json
>>> print(json.dumps({'6': 7, '4': 5}, sort_keys=True, indent=4))
{
    "4": 5,
    "6": 7
}
```

Customizing JSON object encoding:

```
>>> import json
>>> def custom_json(obj):
...     if isinstance(obj, complex):
...         return {'__complex__': True, 'real': obj.real, 'imag': obj.imag}
...     raise TypeError(f'Cannot serialize object of {type(obj)}')
...
>>> json.dumps(1 + 2j, default=custom_json)
'{"__complex__": true, "real": 1.0, "imag": 2.0}'
```

Decoding JSON:

```
>>> import json
>>> json.loads('["foo", {"bar":["baz", null, 1.0, 2]}]')
['foo', {'bar': ['baz', None, 1.0, 2]}]
>>> json.loads('"\\"foo\\bar"')
'"foo\x08ar'
>>> from io import StringIO
>>> io = StringIO('["streaming API"]')
>>> json.load(io)
['streaming API']
```

Customizing JSON object decoding:

```
>>> import json
>>> def as_complex(dct):
...     if '__complex__' in dct:
...         return complex(dct['real'], dct['imag'])
...     return dct
...
>>> json.loads('{"__complex__": true, "real": 1, "imag": 2}',
...     object_hook=as_complex)
(1+2j)
>>> import decimal
>>> json.loads('1.1', parse_float=decimal.Decimal)
Decimal('1.1')
>>> json.loads('{"name": "point", "coords": [[1, 2], [3, 4]]}',
...     array_hook=tuple)
{'name': 'point', 'coords': ((1, 2), (3, 4))}
>>> json.loads('{"name": "point", "coords": [1, 2]}',
...     object_pairs_hook=frozendict, array_hook=tuple)
frozendict({'name': 'point', 'coords': (1, 2)})
```

Extending [`JSONEncoder`](https://docs.python.org/3/library/json.html#json.JSONEncoder "json.JSONEncoder"):

```
>>> import json
>>> class ComplexEncoder(json.JSONEncoder):
...     def default(self, obj):
...         if isinstance(obj, complex):
...             return [obj.real, obj.imag]
...         # Let the base class default method raise the TypeError
...         return super().default(obj)
...
>>> json.dumps(2 + 1j, cls=ComplexEncoder)
'[2.0, 1.0]'
>>> ComplexEncoder().encode(2 + 1j)
'[2.0, 1.0]'
>>> list(ComplexEncoder().iterencode(2 + 1j))
['[2.0', ', 1.0', ']']
```

Using `json` from the shell to validate and pretty-print:

```
$ echo '{"json":"obj"}' | python -m json
{
    "json": "obj"
}
$ echo '{1.2:3.4}' | python -m json
Expecting property name enclosed in double quotes: line 1 column 2 (char 1)
```

See [Command-line interface](https://docs.python.org/3/library/json.html#json-commandline) for detailed documentation.

Note

JSON is a subset of [YAML](https://yaml.org/) 1.2. The JSON produced by this module’s default settings (in particular, the default *separators* value) is also a subset of YAML 1.0 and 1.1. This module can thus also be used as a YAML serializer.

Note

This module’s encoders and decoders preserve input and output order by default. Order is only lost if the underlying containers are unordered.

## Basic Usage[¶](https://docs.python.org/3/library/json.html#basic-usage "Link to this heading")

json.dump(*obj*, *fp*, *\**, *skipkeys=False*, *ensure\_ascii=True*, *check\_circular=True*, *allow\_nan=True*, *cls=None*, *indent=None*, *separators=None*, *default=None*, *sort\_keys=False*, *\*\*kw*)[¶](https://docs.python.org/3/library/json.html#json.dump "Link to this definition")

Serialize *obj* as a JSON formatted stream to *fp* (a `.write()`-supporting [file-like object](https://docs.python.org/3/glossary.html#term-file-like-object)) using this [Python-to-JSON conversion table](https://docs.python.org/3/library/json.html#py-to-json-table).

Note

Unlike [`pickle`](https://docs.python.org/3/library/pickle.html#module-pickle "pickle: Convert Python objects to streams of bytes and back.") and [`marshal`](https://docs.python.org/3/library/marshal.html#module-marshal "marshal: Convert Python objects to streams of bytes and back (with different constraints)."), JSON is not a framed protocol, so trying to serialize multiple objects with repeated calls to `dump()` using the same *fp* will result in an invalid JSON file.

Parameters:

- **obj** ([*object*](https://docs.python.org/3/builtins/functions.html#object "object")) – The Python object to be serialized.
- **fp** ([file-like object](https://docs.python.org/3/glossary.html#term-file-like-object)) – The file-like object *obj* will be serialized to. The `json` module always produces [`str`](https://docs.python.org/3/builtins/stdtypes.html#str "str") objects, not [`bytes`](https://docs.python.org/3/builtins/stdtypes.html#bytes "bytes") objects, therefore `fp.write()` must support `str` input.
- **skipkeys** ([*bool*](https://docs.python.org/3/builtins/functions.html#bool "bool")) – If `True`, keys that are not of a basic type ([`str`](https://docs.python.org/3/builtins/stdtypes.html#str "str"), [`int`](https://docs.python.org/3/builtins/functions.html#int "int"), [`float`](https://docs.python.org/3/builtins/functions.html#float "float"), `bool`, `None`) will be skipped instead of raising a [`TypeError`](https://docs.python.org/3/builtins/exceptions.html#TypeError "TypeError"). Default `False`.
- **ensure\_ascii** ([*bool*](https://docs.python.org/3/builtins/functions.html#bool "bool")) – If `True` (the default), the output is guaranteed to have all incoming non-ASCII and non-printable characters escaped. If `False`, all characters will be outputted as-is, except for the characters that must be escaped: quotation mark, reverse solidus, and the control characters U+0000 through U+001F.
- **check\_circular** ([*bool*](https://docs.python.org/3/builtins/functions.html#bool "bool")) – If `False`, the circular reference check for container types is skipped and a circular reference will result in a [`RecursionError`](https://docs.python.org/3/builtins/exceptions.html#RecursionError "RecursionError") (or worse). Default `True`.
- **allow\_nan** ([*bool*](https://docs.python.org/3/builtins/functions.html#bool "bool")) – If `False`, serialization of out-of-range [`float`](https://docs.python.org/3/builtins/functions.html#float "float") values (`nan`, `inf`, `-inf`) will result in a [`ValueError`](https://docs.python.org/3/builtins/exceptions.html#ValueError "ValueError"), in strict compliance with the JSON specification. If `True` (the default), their JavaScript equivalents (`NaN`, `Infinity`, `-Infinity`) are used.
- **cls** (a [`JSONEncoder`](https://docs.python.org/3/library/json.html#json.JSONEncoder "json.JSONEncoder") subclass) – If set, a custom JSON encoder with the [`default()`](https://docs.python.org/3/library/json.html#json.JSONEncoder.default "json.JSONEncoder.default") method overridden, for serializing into custom datatypes. If `None` (the default), `JSONEncoder` is used.
- **indent** ([*int*](https://docs.python.org/3/builtins/functions.html#int "int") *|* [*str*](https://docs.python.org/3/builtins/stdtypes.html#str "str") *| None*) – If a positive integer or string, JSON array elements and object members will be pretty-printed with that indent level. A positive integer indents that many spaces per level; a string (such as `"\t"`) is used to indent each level. If zero, negative, or `""` (the empty string), only newlines are inserted. If `None` (the default), no newlines are inserted.
- **separators** ([*tuple*](https://docs.python.org/3/builtins/stdtypes.html#tuple "tuple") *| None*) – A two-tuple: `(item_separator, key_separator)`. If `None` (the default), *separators* defaults to `(', ', ': ')` if *indent* is `None`, and `(',', ': ')` otherwise. For the most compact JSON, specify `(',', ':')` to eliminate whitespace.
- **default** ([callable](https://docs.python.org/3/glossary.html#term-callable) | None) – A function that is called for objects that can’t otherwise be serialized. It should return a JSON encodable version of the object or raise a [`TypeError`](https://docs.python.org/3/builtins/exceptions.html#TypeError "TypeError"). If `None` (the default), `TypeError` is raised.
- **sort\_keys** ([*bool*](https://docs.python.org/3/builtins/functions.html#bool "bool")) – If `True`, dictionaries will be outputted sorted by key. Default `False`.

Note

Keys in key/value pairs of JSON are always of the type [`str`](https://docs.python.org/3/builtins/stdtypes.html#str "str"). When a dictionary is converted into JSON, all the keys of the dictionary are converted to strings. As a result of this, if a dictionary is converted into JSON and then back into a dictionary, the dictionary may not equal the original one. That is, `loads(dumps(x)) != x` if x has non-string keys. *sort\_keys* sorts the keys before they are converted to strings, so numeric keys are sorted by value, not by their string representation.

Changed in version 3.2: Allow strings for *indent* in addition to integers.

Changed in version 3.4: Use `(',', ': ')` as default if *indent* is not `None`.

Changed in version 3.6: All optional parameters are now [keyword-only](https://docs.python.org/3/glossary.html#keyword-only-parameter).

json.dumps(*obj*, *\**, *skipkeys=False*, *ensure\_ascii=True*, *check\_circular=True*, *allow\_nan=True*, *cls=None*, *indent=None*, *separators=None*, *default=None*, *sort\_keys=False*, *\*\*kw*)[¶](https://docs.python.org/3/library/json.html#json.dumps "Link to this definition")

Serialize *obj* to a JSON formatted [`str`](https://docs.python.org/3/builtins/stdtypes.html#str "str") using this [conversion table](https://docs.python.org/3/library/json.html#py-to-json-table). The arguments have the same meaning as in [`dump()`](https://docs.python.org/3/library/json.html#json.dump "json.dump").

json.load(*fp*, *\**, *cls=None*, *object\_hook=None*, *parse\_float=None*, *parse\_int=None*, *parse\_constant=None*, *object\_pairs\_hook=None*, *array\_hook=None*, *\*\*kw*)[¶](https://docs.python.org/3/library/json.html#json.load "Link to this definition")

Deserialize *fp* to a Python object using the [JSON-to-Python conversion table](https://docs.python.org/3/library/json.html#json-to-py-table).

Parameters:

- **fp** ([file-like object](https://docs.python.org/3/glossary.html#term-file-like-object)) – A `.read()`-supporting [text file](https://docs.python.org/3/glossary.html#term-text-file) or [binary file](https://docs.python.org/3/glossary.html#term-binary-file) containing the JSON document to be deserialized.
- **cls** (a [`JSONDecoder`](https://docs.python.org/3/library/json.html#json.JSONDecoder "json.JSONDecoder") subclass) – If set, a custom JSON decoder. Additional keyword arguments to `load()` will be passed to the constructor of *cls*. If `None` (the default), `JSONDecoder` is used.
- **object\_hook** ([callable](https://docs.python.org/3/glossary.html#term-callable) | None) – If set, a function that is called with the result of any JSON object literal decoded (a [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict "dict")). The return value of this function will be used instead of the `dict`. This feature can be used to implement custom decoders, for example [JSON-RPC](https://www.jsonrpc.org) class hinting. Default `None`.
- **object\_pairs\_hook** ([callable](https://docs.python.org/3/glossary.html#term-callable) | None) – If set, a function that is called with the result of any JSON object literal decoded with an ordered list of pairs. The return value of this function will be used instead of the [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict "dict"). This feature can be used to implement custom decoders. If *object\_hook* is also set, *object\_pairs\_hook* takes priority. Default `None`.
- **array\_hook** ([callable](https://docs.python.org/3/glossary.html#term-callable) | None) – If set, a function that is called with the result of any JSON array literal decoded as a Python list. The return value of this function will be used instead of the [`list`](https://docs.python.org/3/builtins/stdtypes.html#list "list"). This feature can be used to implement custom decoders. Default `None`.
- **parse\_float** ([callable](https://docs.python.org/3/glossary.html#term-callable) | None) – If set, a function that is called with the string of every JSON float to be decoded. If `None` (the default), it is equivalent to `float(num_str)`. This can be used to parse JSON floats into custom datatypes, for example [`decimal.Decimal`](https://docs.python.org/3/library/decimal.html#decimal.Decimal "decimal.Decimal").
- **parse\_int** ([callable](https://docs.python.org/3/glossary.html#term-callable) | None) – If set, a function that is called with the string of every JSON int to be decoded. If `None` (the default), it is equivalent to `int(num_str)`. This can be used to parse JSON integers into custom datatypes, for example [`float`](https://docs.python.org/3/builtins/functions.html#float "float").
- **parse\_constant** ([callable](https://docs.python.org/3/glossary.html#term-callable) | None) – If set, a function that is called with one of the following strings: `'-Infinity'`, `'Infinity'`, or `'NaN'`. This can be used to raise an exception if invalid JSON numbers are encountered. Default `None`.

Raises:

- [**JSONDecodeError**](https://docs.python.org/3/library/json.html#json.JSONDecodeError "json.JSONDecodeError") – When the data being deserialized is not a valid JSON document.
- [**UnicodeDecodeError**](https://docs.python.org/3/builtins/exceptions.html#UnicodeDecodeError "UnicodeDecodeError") – When the data being deserialized does not contain UTF-8, UTF-16 or UTF-32 encoded data.

Changed in version 3.1:

- Added the optional *object\_pairs\_hook* parameter.
- *parse\_constant* doesn’t get called on ‘null’, ‘true’, ‘false’ anymore.

Changed in version 3.6:

- All optional parameters are now [keyword-only](https://docs.python.org/3/glossary.html#keyword-only-parameter).
- *fp* can now be a [binary file](https://docs.python.org/3/glossary.html#term-binary-file). The input encoding should be UTF-8, UTF-16 or UTF-32.

Changed in version 3.11: The default *parse\_int* of [`int()`](https://docs.python.org/3/builtins/functions.html#int "int") now limits the maximum length of the integer string via the interpreter’s [integer string conversion length limitation](https://docs.python.org/3/builtins/stdtypes.html#int-max-str-digits) to help avoid denial of service attacks.

Changed in version 3.15: Added the optional *array\_hook* parameter.

json.loads(*s*, *\**, *cls=None*, *object\_hook=None*, *parse\_float=None*, *parse\_int=None*, *parse\_constant=None*, *object\_pairs\_hook=None*, *array\_hook=None*, *\*\*kw*)[¶](https://docs.python.org/3/library/json.html#json.loads "Link to this definition")

Identical to [`load()`](https://docs.python.org/3/library/json.html#json.load "json.load"), but instead of a file-like object, deserialize *s* (a [`str`](https://docs.python.org/3/builtins/stdtypes.html#str "str"), [`bytes`](https://docs.python.org/3/builtins/stdtypes.html#bytes "bytes") or [`bytearray`](https://docs.python.org/3/builtins/stdtypes.html#bytearray "bytearray") instance containing a JSON document) to a Python object using this [conversion table](https://docs.python.org/3/library/json.html#json-to-py-table).

Changed in version 3.6: *s* can now be of type [`bytes`](https://docs.python.org/3/builtins/stdtypes.html#bytes "bytes") or [`bytearray`](https://docs.python.org/3/builtins/stdtypes.html#bytearray "bytearray"). The input encoding should be UTF-8, UTF-16 or UTF-32.

Changed in version 3.9: The keyword argument *encoding* has been removed.

## Encoders and Decoders[¶](https://docs.python.org/3/library/json.html#encoders-and-decoders "Link to this heading")

*class* json.JSONDecoder(*\**, *object\_hook=None*, *parse\_float=None*, *parse\_int=None*, *parse\_constant=None*, *strict=True*, *object\_pairs\_hook=None*, *array\_hook=None*)[¶](https://docs.python.org/3/library/json.html#json.JSONDecoder "Link to this definition")

Simple JSON decoder.

Performs the following translations in decoding by default:

| JSON          | Python |
|---------------|--------|
| object        | dict   |
| array         | list   |
| string        | str    |
| number (int)  | int    |
| number (real) | float  |
| true          | True   |
| false         | False  |
| null          | None   |

It also understands `NaN`, `Infinity`, and `-Infinity` as their corresponding `float` values, which is outside the JSON spec.

*object\_hook* is an optional function that will be called with the result of every JSON object decoded and its return value will be used in place of the given [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict "dict"). This can be used to provide custom deserializations (e.g. to support [JSON-RPC](https://www.jsonrpc.org) class hinting).

*object\_pairs\_hook* is an optional function that will be called with the result of every JSON object decoded with an ordered list of pairs. The return value of *object\_pairs\_hook* will be used instead of the [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict "dict"). This feature can be used to implement custom decoders. If *object\_hook* is also defined, the *object\_pairs\_hook* takes priority.

Changed in version 3.1: Added support for *object\_pairs\_hook*.

*array\_hook* is an optional function that will be called with the result of every JSON array decoded as a list. The return value of *array\_hook* will be used instead of the [`list`](https://docs.python.org/3/builtins/stdtypes.html#list "list"). This feature can be used to implement custom decoders.

Changed in version 3.15: Added support for *array\_hook*.

*parse\_float* is an optional function that will be called with the string of every JSON float to be decoded. By default, this is equivalent to `float(num_str)`. This can be used to use another datatype or parser for JSON floats (e.g. [`decimal.Decimal`](https://docs.python.org/3/library/decimal.html#decimal.Decimal "decimal.Decimal")).

*parse\_int* is an optional function that will be called with the string of every JSON int to be decoded. By default, this is equivalent to `int(num_str)`. This can be used to use another datatype or parser for JSON integers (e.g. [`float`](https://docs.python.org/3/builtins/functions.html#float "float")).

*parse\_constant* is an optional function that will be called with one of the following strings: `'-Infinity'`, `'Infinity'`, `'NaN'`. This can be used to raise an exception if invalid JSON numbers are encountered.

If *strict* is false (`True` is the default), then control characters will be allowed inside strings. Control characters in this context are those with character codes in the 0–31 range, including `'\t'` (tab), `'\n'`, `'\r'` and `'\0'`.

If the data being deserialized is not a valid JSON document, a [`JSONDecodeError`](https://docs.python.org/3/library/json.html#json.JSONDecodeError "json.JSONDecodeError") will be raised.

Changed in version 3.6: All parameters are now [keyword-only](https://docs.python.org/3/glossary.html#keyword-only-parameter).

decode(*s*)[¶](https://docs.python.org/3/library/json.html#json.JSONDecoder.decode "Link to this definition")

Return the Python representation of *s* (a [`str`](https://docs.python.org/3/builtins/stdtypes.html#str "str") instance containing a JSON document).

[`JSONDecodeError`](https://docs.python.org/3/library/json.html#json.JSONDecodeError "json.JSONDecodeError") will be raised if the given JSON document is not valid.

raw\_decode(*s*)[¶](https://docs.python.org/3/library/json.html#json.JSONDecoder.raw_decode "Link to this definition")

Decode a JSON document from *s* (a [`str`](https://docs.python.org/3/builtins/stdtypes.html#str "str") beginning with a JSON document) and return a 2-tuple of the Python representation and the index in *s* where the document ended.

This can be used to decode a JSON document from a string that may have extraneous data at the end.

*class* json.JSONEncoder(*\**, *skipkeys=False*, *ensure\_ascii=True*, *check\_circular=True*, *allow\_nan=True*, *sort\_keys=False*, *indent=None*, *separators=None*, *default=None*)[¶](https://docs.python.org/3/library/json.html#json.JSONEncoder "Link to this definition")

Extensible JSON encoder for Python data structures.

Supports the following objects and types by default:

| Python                                 | JSON   |
|----------------------------------------|--------|
| dict, frozendict                       | object |
| list, tuple                            | array  |
| str                                    | string |
| int, float, int- & float-derived Enums | number |
| True                                   | true   |
| False                                  | false  |
| None                                   | null   |

Changed in version 3.4: Added support for int- and float-derived Enum classes.

Changed in version 3.15: Added support for [`frozendict`](https://docs.python.org/3/builtins/stdtypes.html#frozendict "frozendict").

To extend this to recognize other objects, subclass and implement a [`default()`](https://docs.python.org/3/library/json.html#json.JSONEncoder.default "json.JSONEncoder.default") method with another method that returns a serializable object for `o` if possible, otherwise it should call the superclass implementation (to raise [`TypeError`](https://docs.python.org/3/builtins/exceptions.html#TypeError "TypeError")).

If *skipkeys* is false (the default), a [`TypeError`](https://docs.python.org/3/builtins/exceptions.html#TypeError "TypeError") will be raised when trying to encode keys that are not [`str`](https://docs.python.org/3/builtins/stdtypes.html#str "str"), [`int`](https://docs.python.org/3/builtins/functions.html#int "int"), [`float`](https://docs.python.org/3/builtins/functions.html#float "float"), [`bool`](https://docs.python.org/3/builtins/functions.html#bool "bool") or `None`. If *skipkeys* is true, such items are simply skipped.

If *ensure\_ascii* is true (the default), the output is guaranteed to have all incoming non-ASCII and non-printable characters escaped. If *ensure\_ascii* is false, all characters will be output as-is, except for the characters that must be escaped: quotation mark, reverse solidus, and the control characters U+0000 through U+001F.

If *check\_circular* is true (the default), then lists, dicts, and custom encoded objects will be checked for circular references during encoding to prevent an infinite recursion (which would cause a [`RecursionError`](https://docs.python.org/3/builtins/exceptions.html#RecursionError "RecursionError")). Otherwise, no such check takes place.

If *allow\_nan* is true (the default), then `NaN`, `Infinity`, and `-Infinity` will be encoded as such. This behavior is not JSON specification compliant, but is consistent with most JavaScript based encoders and decoders. Otherwise, it will be a [`ValueError`](https://docs.python.org/3/builtins/exceptions.html#ValueError "ValueError") to encode such floats.

If *sort\_keys* is true (default: `False`), then the output of dictionaries will be sorted by key; this is useful for regression tests to ensure that JSON serializations can be compared on a day-to-day basis.

If *indent* is a non-negative integer or string, then JSON array elements and object members will be pretty-printed with that indent level. An indent level of 0, negative, or `""` will only insert newlines. `None` (the default) selects the most compact representation. Using a positive integer indent indents that many spaces per level. If *indent* is a string (such as `"\t"`), that string is used to indent each level.

Changed in version 3.2: Allow strings for *indent* in addition to integers.

If specified, *separators* should be an `(item_separator, key_separator)` tuple. The default is `(', ', ': ')` if *indent* is `None` and `(',', ': ')` otherwise. To get the most compact JSON representation, you should specify `(',', ':')` to eliminate whitespace.

Changed in version 3.4: Use `(',', ': ')` as default if *indent* is not `None`.

If specified, *default* should be a function that gets called for objects that can’t otherwise be serialized. It should return a JSON encodable version of the object or raise a [`TypeError`](https://docs.python.org/3/builtins/exceptions.html#TypeError "TypeError"). If not specified, `TypeError` is raised.

Changed in version 3.6: All parameters are now [keyword-only](https://docs.python.org/3/glossary.html#keyword-only-parameter).

default(*o*)[¶](https://docs.python.org/3/library/json.html#json.JSONEncoder.default "Link to this definition")

Implement this method in a subclass such that it returns a serializable object for *o*, or calls the base implementation (to raise a [`TypeError`](https://docs.python.org/3/builtins/exceptions.html#TypeError "TypeError")).

For example, to support arbitrary iterators, you could implement `default()` like this:

```
def default(self, o):
   try:
       iterable = iter(o)
   except TypeError:
       pass
   else:
       return list(iterable)
   # Let the base class default method raise the TypeError
   return super().default(o)
```

encode(*o*)[¶](https://docs.python.org/3/library/json.html#json.JSONEncoder.encode "Link to this definition")

Return a JSON string representation of a Python data structure, *o*. For example:

```
>>> json.JSONEncoder().encode({"foo": ["bar", "baz"]})
'{"foo": ["bar", "baz"]}'
```

iterencode(*o*)[¶](https://docs.python.org/3/library/json.html#json.JSONEncoder.iterencode "Link to this definition")

Encode the given object, *o*, and yield each string representation as available. For example:

```
for chunk in json.JSONEncoder().iterencode(bigobject):
    mysocket.write(chunk)
```

## Exceptions[¶](https://docs.python.org/3/library/json.html#exceptions "Link to this heading")

*exception* json.JSONDecodeError(*msg*, *doc*, *pos*)[¶](https://docs.python.org/3/library/json.html#json.JSONDecodeError "Link to this definition")

Subclass of [`ValueError`](https://docs.python.org/3/builtins/exceptions.html#ValueError "ValueError") with the following additional attributes:

msg[¶](https://docs.python.org/3/library/json.html#json.JSONDecodeError.msg "Link to this definition")

The unformatted error message.

doc[¶](https://docs.python.org/3/library/json.html#json.JSONDecodeError.doc "Link to this definition")

The JSON document being parsed.

pos[¶](https://docs.python.org/3/library/json.html#json.JSONDecodeError.pos "Link to this definition")

The start index of *doc* where parsing failed.

lineno[¶](https://docs.python.org/3/library/json.html#json.JSONDecodeError.lineno "Link to this definition")

The line corresponding to *pos*.

colno[¶](https://docs.python.org/3/library/json.html#json.JSONDecodeError.colno "Link to this definition")

The column corresponding to *pos*.

Added in version 3.5.

## Standard Compliance and Interoperability[¶](https://docs.python.org/3/library/json.html#standard-compliance-and-interoperability "Link to this heading")

The JSON format is specified by [**RFC 7159**](https://datatracker.ietf.org/doc/html/rfc7159.html) and by [ECMA-404](https://ecma-international.org/publications-and-standards/standards/ecma-404/). This section details this module’s level of compliance with the RFC. For simplicity, [`JSONEncoder`](https://docs.python.org/3/library/json.html#json.JSONEncoder "json.JSONEncoder") and [`JSONDecoder`](https://docs.python.org/3/library/json.html#json.JSONDecoder "json.JSONDecoder") subclasses, and parameters other than those explicitly mentioned, are not considered.

This module does not comply with the RFC in a strict fashion, implementing some extensions that are valid JavaScript but not valid JSON. In particular:

- Infinite and NaN number values are accepted and output;
- Repeated names within an object are accepted, and only the value of the last name-value pair is used.

Since the RFC permits RFC-compliant parsers to accept input texts that are not RFC-compliant, this module’s deserializer is technically RFC-compliant under default settings.

### Character Encodings[¶](https://docs.python.org/3/library/json.html#character-encodings "Link to this heading")

The RFC requires that JSON be represented using either UTF-8, UTF-16, or UTF-32, with UTF-8 being the recommended default for maximum interoperability.

As permitted, though not required, by the RFC, this module’s serializer sets *ensure\_ascii=True* by default, thus escaping the output so that the resulting strings only contain printable ASCII characters.

Other than the *ensure\_ascii* parameter, this module is defined strictly in terms of conversion between Python objects and [`Unicode strings`](https://docs.python.org/3/builtins/stdtypes.html#str "str"), and thus does not otherwise directly address the issue of character encodings.

The RFC prohibits adding a byte order mark (BOM) to the start of a JSON text, and this module’s serializer does not add a BOM to its output. The RFC permits, but does not require, JSON deserializers to ignore an initial BOM in their input. This module’s deserializer raises a [`ValueError`](https://docs.python.org/3/builtins/exceptions.html#ValueError "ValueError") when an initial BOM is present.

The RFC does not explicitly forbid JSON strings which contain byte sequences that don’t correspond to valid Unicode characters (e.g. unpaired UTF-16 surrogates), but it does note that they may cause interoperability problems. By default, this module accepts and outputs (when present in the original [`str`](https://docs.python.org/3/builtins/stdtypes.html#str "str")) code points for such sequences.

### Infinite and NaN Number Values[¶](https://docs.python.org/3/library/json.html#infinite-and-nan-number-values "Link to this heading")

The RFC does not permit the representation of infinite or NaN number values. Despite that, by default, this module accepts and outputs `Infinity`, `-Infinity`, and `NaN` as if they were valid JSON number literal values:

```
>>> # Neither of these calls raises an exception, but the results are not valid JSON
>>> json.dumps(float('-inf'))
'-Infinity'
>>> json.dumps(float('nan'))
'NaN'
>>> # Same when deserializing
>>> json.loads('-Infinity')
-inf
>>> json.loads('NaN')
nan
```

In the serializer, the *allow\_nan* parameter can be used to alter this behavior. In the deserializer, the *parse\_constant* parameter can be used to alter this behavior.

### Repeated Names Within an Object[¶](https://docs.python.org/3/library/json.html#repeated-names-within-an-object "Link to this heading")

The RFC specifies that the names within a JSON object should be unique, but does not mandate how repeated names in JSON objects should be handled. By default, this module does not raise an exception; instead, it ignores all but the last name-value pair for a given name:

```
>>> weird_json = '{"x": 1, "x": 2, "x": 3}'
>>> json.loads(weird_json)
{'x': 3}
```

The *object\_pairs\_hook* parameter can be used to alter this behavior.

### Top-level Non-Object, Non-Array Values[¶](https://docs.python.org/3/library/json.html#top-level-non-object-non-array-values "Link to this heading")

The old version of JSON specified by the obsolete [**RFC 4627**](https://datatracker.ietf.org/doc/html/rfc4627.html) required that the top-level value of a JSON text must be either a JSON object or array (Python [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict "dict") or [`list`](https://docs.python.org/3/builtins/stdtypes.html#list "list")), and could not be a JSON null, boolean, number, or string value. [**RFC 7159**](https://datatracker.ietf.org/doc/html/rfc7159.html) removed that restriction, and this module does not and has never implemented that restriction in either its serializer or its deserializer.

Regardless, for maximum interoperability, you may wish to voluntarily adhere to the restriction yourself.

### Implementation Limitations[¶](https://docs.python.org/3/library/json.html#implementation-limitations "Link to this heading")

Some JSON deserializer implementations may set limits on:

- the size of accepted JSON texts
- the maximum level of nesting of JSON objects and arrays
- the range and precision of JSON numbers
- the content and maximum length of JSON strings

This module does not impose any such limits beyond those of the relevant Python datatypes themselves or the Python interpreter itself.

When serializing to JSON, beware any such limitations in applications that may consume your JSON. In particular, it is common for JSON numbers to be deserialized into IEEE 754 double precision numbers and thus subject to that representation’s range and precision limitations. This is especially relevant when serializing Python [`int`](https://docs.python.org/3/builtins/functions.html#int "int") values of extremely large magnitude, or when serializing instances of “exotic” numerical types such as [`decimal.Decimal`](https://docs.python.org/3/library/decimal.html#decimal.Decimal "decimal.Decimal").

## Command-line interface[¶](https://docs.python.org/3/library/json.html#module-json.tool "Link to this heading")

**Source code:** [Lib/json/tool.py](https://github.com/python/cpython/tree/3.15/Lib/json/tool.py)

* * *

The `json` module can be invoked as a script via `python -m json` to validate and pretty-print JSON objects. The `json.tool` submodule implements this interface.

If the optional `infile` and `outfile` arguments are not specified, [`sys.stdin`](https://docs.python.org/3/library/sys.html#sys.stdin "sys.stdin") and [`sys.stdout`](https://docs.python.org/3/library/sys.html#sys.stdout "sys.stdout") will be used respectively:

```
$ echo '{"json": "obj"}' | python -m json
{
    "json": "obj"
}
$ echo '{1.2:3.4}' | python -m json
Expecting property name enclosed in double quotes: line 1 column 2 (char 1)
```

Changed in version 3.5: The output is now in the same order as the input. Use the [`--sort-keys`](https://docs.python.org/3/library/json.html#cmdoption-json-sort-keys) option to sort the output of dictionaries alphabetically by key.

Changed in version 3.14: The `json` module may now be directly executed as `python -m json`. For backwards compatibility, invoking the CLI as `python -m json.tool` remains supported.

### Command-line options[¶](https://docs.python.org/3/library/json.html#command-line-options "Link to this heading")

infile[¶](https://docs.python.org/3/library/json.html#cmdoption-json-arg-infile "Link to this definition")

The JSON file to be validated or pretty-printed:

```
$ python -m json mp_films.json
[
    {
        "title": "And Now for Something Completely Different",
        "year": 1971
    },
    {
        "title": "Monty Python and the Holy Grail",
        "year": 1975
    }
]
```

If *infile* is not specified, read from [`sys.stdin`](https://docs.python.org/3/library/sys.html#sys.stdin "sys.stdin").

outfile[¶](https://docs.python.org/3/library/json.html#cmdoption-json-arg-outfile "Link to this definition")

Write the output of the *infile* to the given *outfile*. Otherwise, write it to [`sys.stdout`](https://docs.python.org/3/library/sys.html#sys.stdout "sys.stdout").

--sort-keys[¶](https://docs.python.org/3/library/json.html#cmdoption-json-sort-keys "Link to this definition")

Sort the output of dictionaries alphabetically by key.

Added in version 3.5.

--no-ensure-ascii[¶](https://docs.python.org/3/library/json.html#cmdoption-json-no-ensure-ascii "Link to this definition")

Disable escaping of non-ascii characters, see [`json.dumps()`](https://docs.python.org/3/library/json.html#json.dumps "json.dumps") for more information.

Added in version 3.9.

--json-lines[¶](https://docs.python.org/3/library/json.html#cmdoption-json-json-lines "Link to this definition")

Parse every input line as separate JSON object.

Added in version 3.8.

--indent, --tab, --no-indent, --compact[¶](https://docs.python.org/3/library/json.html#cmdoption-json-indent "Link to this definition")

Mutually exclusive options for whitespace control.

Added in version 3.9.

-h, --help[¶](https://docs.python.org/3/library/json.html#cmdoption-json-h "Link to this definition")

Show the help message.

Footnotes

\[[1](https://docs.python.org/3/library/json.html#id1)]

As noted in [the errata for RFC 7159](https://www.rfc-editor.org/errata_search.php?rfc=7159), JSON permits literal U+2028 (LINE SEPARATOR) and U+2029 (PARAGRAPH SEPARATOR) characters in strings, whereas JavaScript (as of ECMAScript Edition 5.1) does not.
