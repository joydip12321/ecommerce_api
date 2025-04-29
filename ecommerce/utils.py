from django.core.cache import cache

class BlacklistedToken:
    def __init__(self, token):
        self.token = token

    def blacklist_token(self):
        cache.set(self.token, 'blacklisted', timeout=3600)

    @staticmethod
    def is_token_blacklisted(token):
        return cache.get(token) is not None

    def __str__(self):
        return self.token
