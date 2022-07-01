import os
from distutils.command.build import build

from django.core import management
from setuptools import find_packages, setup

from pretix_oidc import __version__


try:
    with open(
        os.path.join(os.path.dirname(__file__), "README.rst"), encoding="utf-8"
    ) as f:
        long_description = f.read()
except Exception:
    long_description = ""


class CustomBuild(build):
    def run(self):
        management.call_command("compilemessages", verbosity=1)
        build.run(self)


cmdclass = {"build": CustomBuild}


setup(
    name="pretix-oidc",
    version=__version__,
    description="This is a plugin for pretix that provides a pluggable authentication backend for OIDC servers.",
    long_description=long_description,
    url="https://github.com/mozilla/mozilla-django-oidc",
    author="Evolutio",
    author_email="jpolonia@evolutio.pt",
    license="Apache",
    install_requires=['josepy'],
    packages=find_packages(exclude=["tests", "tests.*"]),
    include_package_data=True,
    cmdclass=cmdclass,
    entry_points="""
[pretix.plugin]
pretix_oidc=pretix_oidc:PretixPluginMeta
""",
)
