# (c) Nelen & Schuurmans, see LICENSE.rst.

from django import template

register = template.Library()


@register.filter
def punctuate(sentence: str) -> str:
    if (rstripped := sentence.rstrip()) and not rstripped.endswith("."):
        return rstripped + "."
    return sentence
