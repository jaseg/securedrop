#!/usr/bin/env python
# -*- coding: utf-8 -*-
import unittest
import re

_empty_re = re.compile('^\s*$')
_comment_re = re.compile('^\s*#')


class ValidationException(Exception):
    pass


def _validate_string(string):
    current_block = []
    for line in string:
        if _empty_re.match(line):
            if not current_block:
                continue
            else:
                current_block.append(line)
        else:
            _validate_block(current_block)
            current_block = []


def _validate_string_fail(string):
    try:
        _validate_string(string)
        assert False, 'String validated when it should not have. String:\n' + string
    except ValidationException:
        pass


def _validate_block(block):
    block = filter(lambda line: _comment_re.match(line), block)

    pass


def _mkstr(msgid, msgstr):
    return ('msgid ""\n'
            'msgstr ""\n\n'
            '#, something.py:123\n'
            'msgid "{id}"\n'
            'msgstr "{str}"\n').format(id=msgid, str=msgstr)


def _mkstr_plural(msgid, msgid_plural, *args):
    string = ('msgid ""\n'
              'msgstr ""\n\n'
              '#, something.py:123\n'
              'msgid "{msgid}"\n'
              'msgid_plural "{msgid_plural}').format(msgid=msgid, msgid_plural=msgid_plural)

    for i, arg in enumerate(args):
        string += '\nmsgstr[{i}] "{msg}"'.format(i=i, msg=arg)

    return string


class TestTranslations:

    def __init__(self):
        pass

    def test_meta(self):
        _validate_string(_mkstr('foo', 'föö'))
        _validate_string(_mkstr('foo <em>bar</em>', 'föö <em>bår</em>'))
        _validate_string(_mkstr('foo <a href="baz.quux">bar</a>', 'föö <a href="baz.quux">bår</a>'))
        _validate_string(_mkstr('foo < bar', 'föö < bår'))
        _validate_string(_mkstr('foo is < bar and > baz', 'föö ist < bår und > bæz'))
        _validate_string(_mkstr('<div foo="bar"/>', '<div foo="bår"/>'))
        _validate_string(_mkstr('{foo} bar', 'bår {foo}'))

        _validate_string_fail(_mkstr('foo <em>bar</bar>', 'föö <em>bår</em'))
        _validate_string_fail(_mkstr('foo <a href="baz.quux">bar</a>', 'föö <a href="baz.quux>bår</a>'))
        _validate_string_fail(_mkstr('{foo} bar', 'bår {fo}'))


if __name__ == "__main__":
    unittest.main(verbosity=2)
