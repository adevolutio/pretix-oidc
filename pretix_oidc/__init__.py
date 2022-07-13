from django.utils.translation import gettext_lazy

try:
    from pretix.base.plugins import PluginConfig
except ImportError:
    raise RuntimeError("Please use pretix 2.7 or above to run this plugin!")

__version__ = "1.0.9"


class PluginApp(PluginConfig):
    name = "pretix_oidc"
    verbose_name = "Mozilla OIDC Auth Backend"

    class PretixPluginMeta:
        name = gettext_lazy("Mozilla OIDC Auth Backend")
        author = "Evolutio"
        description = gettext_lazy(
            "This is a plugin for pretix that provides a pluggable authentication backend for OIDC servers."
        )
        visible = True
        version = __version__
        category = "INTEGRATION"
        compatibility = "pretix>=4.0.0"

    def ready(self):
        from . import signals  # NOQA


default_app_config = "pretix_oidc.PluginApp"
