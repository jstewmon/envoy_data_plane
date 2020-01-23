# Generated by the protocol buffer compiler.  DO NOT EDIT!
# sources: envoy/type/matcher/regex.proto, envoy/type/matcher/string.proto
# plugin: python-betterproto
from dataclasses import dataclass
from typing import List, Optional

import betterproto


@dataclass
class RegexMatcher(betterproto.Message):
    """A regex matcher designed for safety when used with untrusted input."""

    # Google's RE2 regex engine.
    google_re2: "RegexMatcherGoogleRE2" = betterproto.message_field(
        1, group="engine_type"
    )
    # The regex match string. The string must be supported by the configured
    # engine.
    regex: str = betterproto.string_field(2)


@dataclass
class RegexMatcherGoogleRE2(betterproto.Message):
    """
    Google's `RE2 <https://github.com/google/re2>`_ regex engine. The regex
    string must adhere to the documented `syntax
    <https://github.com/google/re2/wiki/Syntax>`_. The engine is designed to
    complete execution in linear time as well as limit the amount of memory
    used.
    """

    # This field controls the RE2 "program size" which is a rough estimate of how
    # complex a compiled regex is to evaluate. A regex that has a program size
    # greater than the configured value will fail to compile. In this case, the
    # configured max program size can be increased or the regex can be
    # simplified. If not specified, the default is 100.
    max_program_size: Optional[int] = betterproto.message_field(
        1, wraps=betterproto.TYPE_UINT32
    )


@dataclass
class StringMatcher(betterproto.Message):
    """Specifies the way to match a string. [#next-free-field: 6]"""

    # The input string must match exactly the string specified here. Examples: *
    # *abc* only matches the value *abc*.
    exact: str = betterproto.string_field(1, group="match_pattern")
    # The input string must have the prefix specified here. Note: empty prefix is
    # not allowed, please use regex instead. Examples: * *abc* matches the value
    # *abc.xyz*
    prefix: str = betterproto.string_field(2, group="match_pattern")
    # The input string must have the suffix specified here. Note: empty prefix is
    # not allowed, please use regex instead. Examples: * *abc* matches the value
    # *xyz.abc*
    suffix: str = betterproto.string_field(3, group="match_pattern")
    # The input string must match the regular expression specified here. The
    # regex grammar is defined `here
    # <https://en.cppreference.com/w/cpp/regex/ecmascript>`_. Examples: * The
    # regex ``\d{3}`` matches the value *123* * The regex ``\d{3}`` does not
    # match the value *1234* * The regex ``\d{3}`` does not match the value
    # *123.456* .. attention::   This field has been deprecated in favor of
    # `safe_regex` as it is not safe for use with   untrusted input in all cases.
    regex: str = betterproto.string_field(4, group="match_pattern")
    # The input string must match the regular expression specified here.
    safe_regex: "RegexMatcher" = betterproto.message_field(5, group="match_pattern")


@dataclass
class ListStringMatcher(betterproto.Message):
    """Specifies a list of ways to match a string."""

    patterns: List["StringMatcher"] = betterproto.message_field(1)