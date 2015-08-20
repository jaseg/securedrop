# -*- coding: utf-8 -*-
import os
import subprocess
from base64 import b32encode

from Crypto.Random import random
import gnupg
import scrypt

import config
import store

# to fix gpg error #78 on production
os.environ['USERNAME'] = 'www-data'

GPG_KEY_TYPE = "RSA"
if os.environ.get('SECUREDROP_ENV') == 'test':
    # Optimize crypto to speed up tests (at the expense of security - DO NOT
    # use these settings in production)
    GPG_KEY_LENGTH = 1024
    SCRYPT_PARAMS = dict(N=2**1, r=1, p=1)
else:
    GPG_KEY_LENGTH = 4096
    SCRYPT_PARAMS = config.SCRYPT_PARAMS

SCRYPT_ID_PEPPER = config.SCRYPT_ID_PEPPER
SCRYPT_GPG_PEPPER = config.SCRYPT_GPG_PEPPER

DEFAULT_WORDS_IN_RANDOM_ID = 8


# Make sure these pass before the app can run
# TODO: Add more tests
def do_runtime_tests():
    assert(config.SCRYPT_ID_PEPPER != config.SCRYPT_GPG_PEPPER)
    # crash if we don't have srm:
    try:
        subprocess.check_call(['srm'], stdout=subprocess.PIPE)
    except subprocess.CalledProcessError:
        pass

do_runtime_tests()

# HACK: use_agent=True is used to avoid logging noise.
#
# --use-agent is a dummy option in gpg2, which is the only version of
# gpg used by SecureDrop. If use_agent=False, gpg2 prints a warning
# message every time it runs because the option is deprecated and has
# no effect. This message cannot be silenced even if you change the
# --debug-level (controlled via the verbose= keyword argument to the
# gnupg.GPG constructor), and creates a lot of logging noise.
#
# The best solution here would be to avoid passing either --use-agent
# or --no-use-agent to gpg2, and I have filed an issue upstream to
# address this: https://github.com/isislovecruft/python-gnupg/issues/96
gpg = gnupg.GPG(binary='gpg2', homedir=config.GPG_KEY_DIR, use_agent=True)

words = {}
nouns = {}
adjectives = {}


class CryptoException(Exception):
    pass


def populate_words():
    if not words:
        for locale in getattr(config, 'LOCALES', ['en_US']):
            words[locale] = file(os.path.join(config.WORDS_DIR, locale, 'wordlist.txt')).read().split('\n')


def populate_nouns():
    if not nouns:
        for locale in getattr(config, 'LOCALES', ['en_US']):
            nouns[locale] = file(os.path.join(config.WORDS_DIR, locale, 'nouns.txt')).read().split('\n')


def populate_adjectives():
    if not adjectives:
        for locale in getattr(config, 'LOCALES', ['en_US']):
            adjectives[locale] = file(os.path.join(config.WORDS_DIR, locale, 'adjectives.txt')).read().split('\n')


populate_words()
populate_nouns()
populate_adjectives()


def clean(string):
    """
    >>> clean("Hello, world!")
    Traceback (most recent call last):
      ...
    CryptoException: invalid input
    >>> clean("Helloworld")
    'Helloworld'
    """
    try:
        # scrypt.hash requires input of type str
        return str(string.decode("utf-8"))
    except UnicodeDecodeError:
        raise CryptoException("invalid input: {0}".format(string))


def genrandomid(locale, words_in_random_id=DEFAULT_WORDS_IN_RANDOM_ID):
    words_for_locale = words.get(locale)
    return ' '.join(random.choice(words_for_locale) for _ in range(words_in_random_id))


def display_id(locale):
    nouns_for_locale = nouns[locale]
    adjs_for_locale = adjectives[locale]
    # TODO Adjectives don't always precede nouns and may be inflected or declined in non-English languages
    return ' '.join([random.choice(adjs_for_locale), random.choice(nouns_for_locale)])


def hash_codename(codename, salt=SCRYPT_ID_PEPPER):
    """
    >>> hash_codename('Hello, world!')
    'EQZGCJBRGISGOTC2NZVWG6LILJBHEV3CINNEWSCLLFTUWZLFHBTS6WLCHFHTOLRSGQXUQLRQHFMXKOKKOQ4WQ6SXGZXDAS3Z'
    """
    return b32encode(scrypt.hash(clean(codename), salt, **SCRYPT_PARAMS))


def genkeypair(name, secret):
    """
    >>> if not gpg.list_keys(hash_codename('randomid')):
    ...     genkeypair(hash_codename('randomid'), 'randomid').type
    ... else:
    ...     u'P'
    u'P'
    """
    name = clean(name)
    secret = hash_codename(secret, salt=SCRYPT_GPG_PEPPER)
    return gpg.gen_key(gpg.gen_key_input(
        key_type=GPG_KEY_TYPE, key_length=GPG_KEY_LENGTH,
        passphrase=secret,
        name_email=name
    ))


def delete_reply_keypair(source_id):
    key = getkey(source_id)
    # If this source was never flagged for review, they won't have a reply
    # keypair
    if not key:
        return
    # The private key needs to be deleted before the public key can be deleted
    # http://pythonhosted.org/python-gnupg/#deleting-keys
    gpg.delete_keys(key, True)  # private key
    gpg.delete_keys(key)  # public key
    # TODO: srm?


def getkey(name):
    for key in gpg.list_keys():
        for uid in key['uids']:
            if name in uid:
                return key['fingerprint']
    return None


def get_key_by_fingerprint(fingerprint):
    matches = [k for k in gpg.list_keys() if k['fingerprint'] == fingerprint]
    return matches[0] if matches else None


def encrypt(plaintext, fingerprints, output=None):
    # Verify the output path
    if output:
        store.verify(output)

    # Remove any spaces from provided fingerprints
    # GPG outputs fingerprints with spaces for readability, but requires the
    # spaces to be removed when using fingerprints to specify recipients.
    if not isinstance(fingerprints, (list, tuple)):
        fingerprints = [fingerprints, ]
    fingerprints = [fpr.replace(' ', '') for fpr in fingerprints]

    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf8')

    encrypt_fn = gpg.encrypt if isinstance(
        plaintext,
        str) else gpg.encrypt_file
    out = encrypt_fn(plaintext,
                     *fingerprints,
                     output=output,
                     always_trust=True,
                     armor=False)
    if out.ok:
        return out.data
    else:
        raise CryptoException(out.stderr)


def decrypt(secret, plain_text):
    """
    >>> key = genkeypair('randomid', 'randomid')
    >>> decrypt('randomid', 'randomid',
    ...   encrypt('randomid', 'Goodbye, cruel world!')
    ... )
    'Goodbye, cruel world!'
    """
    hashed_codename = hash_codename(secret, salt=SCRYPT_GPG_PEPPER)
    return gpg.decrypt(plain_text, passphrase=hashed_codename).data


if __name__ == "__main__":
    import doctest
    doctest.testmod()
