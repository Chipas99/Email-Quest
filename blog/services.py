from django.core.cache import cache

from blog.models import Blogpost
from config.settings import CACHE_ENABLED


def get_cache_blogposts():
    if CACHE_ENABLED:
        key = 'blogposts'
        blogposts = cache.get(key)
        if blogposts is None:
            blogposts = Blogpost.objects.all()
            cache.set(key, blogposts)
    else:
        blogposts = Blogpost.objects.all()
    return blogposts
