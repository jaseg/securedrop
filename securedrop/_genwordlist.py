"""
Generates `wordlist` from The English Open Word List http://dreamsteep.com/projects/the-english-open-word-list.html
Usage: Unzip the CSV files from the archive with the command `unzip EOWL-v1.1.2.zip EOWL-v1.1.2/CSV\ Format/*.csv`
"""
import config
import os
import re
import string


def just7(x):
    return all(c in string.printable for c in x)


def filter_word_list(words, output_func):
    # punctuation is right out
    punctuation_re = re.compile(r'[{}]'.format(re.escape(string.punctuation)), re.UNICODE)

    # assume things like 'yyyy' are not a real words in any language
    repeated_re = re.compile(r'^(.)\1{3,}', re.UNICODE)

    # skip bigrams xf, xg, xh, etc.
    bigram_re = re.compile(r'^(.){2}$', re.UNICODE)

    for word in words:
        if punctuation_re.search(word) or repeated_re.search(word) or bigram_re.search(word):
            continue
        else:
            output_func(word)

if getattr(config, 'env', 'prod') == 'prod':
    word_set = set()
    for i in map(chr, list(range(65, 91))):
        word_set.update(
            x.strip() for x in file(
                'EOWL-v1.1.2/CSV Format/%s Words.csv' %
                i) if just7(x))

    fh = file(os.path.join('dictionaries', 'en_US', 'wordlist.txt'), 'w')
    filter_word_list(word_set, lambda word: fh.write(word + "\n"))
