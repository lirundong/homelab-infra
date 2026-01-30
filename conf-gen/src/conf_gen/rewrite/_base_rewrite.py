class RewriteBase:
    def __init__(self, name, url):
        self.name = name
        self.url = url
        self._rewrites = []

    @property
    def quantumult_rewrite(self):
        raise NotImplementedError()

    @property
    def clash_rewrite(self):
        raise NotImplementedError()
