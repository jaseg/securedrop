#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import unittest

from _genwordlist import filter_word_list

# Set environment variable so config.py uses a test environment
os.environ['SECUREDROP_ENV'] = 'test'


class TestGenwordlist:

    def __index__(self):
        pass

    def test_accepts_valid_ascii(self):
        words = {'foo', 'bar', 'baz'}
        output = set()
        filter_word_list(words, lambda word: output.add(word))
        assert output == words

    def test_accepts_valid_unicode(self):
        words = {u'föö', u'bår', u'bæz'}
        output = set()
        filter_word_list(words, lambda word: output.add(word))
        assert output == words

    def test_rejects_punctuation(self):
        words = {'foo.', '!bar', 'b{a}z', u'quüx?'}
        output = set()
        filter_word_list(words, lambda word: output.add(word))
        assert not output

    def test_rejects_bigrams(self):
        words = {'aa', 'ab', u'öö', u'oö'}
        output = set()
        filter_word_list(words, lambda word: output.add(word))
        assert not output

    def test_rejects_repeated_char_words(self):
        words = {'aaaa', u'öööö', 'aaaaaaaa', 'aaaabcde'}
        output = set()
        filter_word_list(words, lambda word: output.add(word))
        assert not output


if __name__ == "__main__":
    unittest.main(verbosity=2)
