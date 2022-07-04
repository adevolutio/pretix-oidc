from django.urls import path

from .views import (
    OIDCAuthenticationCallbackView,
    OIDCAuthenticationRequestView,
    OIDCLogoutView,
)

urlpatterns = [
    path(
        "callback/",
        OIDCAuthenticationCallbackView.as_view(),
        name="oidc_authentication_callback",
    ),
    path(
        "authenticate/",
        OIDCAuthenticationRequestView.as_view(),
        name="oidc_authentication_init",
    ),
    path("logout/", OIDCLogoutView.as_view(), name="oidc_logout"),
]
