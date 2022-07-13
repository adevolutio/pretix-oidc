import json
import logging
import requests
from django.contrib import messages
from django.core.exceptions import ImproperlyConfigured, SuspiciousOperation
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.encoding import force_bytes, smart_bytes, smart_str
from django.utils.translation import gettext_lazy as _
from josepy.b64 import b64decode
from josepy.jwk import JWK
from josepy.jws import JWS, Header
from pretix.base.auth import BaseAuthBackend
from pretix.base.models import User, Organizer, Team, Event
from pretix.base.models.auth import EmailAddressTakenError
from pretix.settings import config
from requests.auth import HTTPBasicAuth
from django.http import Http404

from .utils import absolutify, import_from_settings
from django_scopes import scope, scopes_disabled

LOGGER = logging.getLogger(__name__)


class OIDCAuthBackend(BaseAuthBackend):
    """
    This class implements the interface for pluggable authentication modules used by pretix.
    """

    """
    A short and unique identifier for this authentication backend.
    This should only contain lowercase letters and in most cases will
    be the same as your package name.
    """
    identifier = "keycloak_auth"

    def __init__(self, *args, **kwargs):
        """Initialize settings."""
        self.OIDC_OP_TOKEN_ENDPOINT = self.get_settings("OIDC_OP_TOKEN_ENDPOINT")
        self.OIDC_OP_USER_ENDPOINT = self.get_settings("OIDC_OP_USER_ENDPOINT")
        self.OIDC_OP_JWKS_ENDPOINT = self.get_settings("OIDC_OP_JWKS_ENDPOINT", None)
        self.OIDC_RP_CLIENT_ID = self.get_settings("OIDC_RP_CLIENT_ID")
        self.OIDC_RP_CLIENT_SECRET = self.get_settings("OIDC_RP_CLIENT_SECRET")
        self.OIDC_RP_SIGN_ALGO = self.get_settings("OIDC_RP_SIGN_ALGO", "HS256")
        self.OIDC_RP_IDP_SIGN_KEY = self.get_settings("OIDC_RP_IDP_SIGN_KEY", None)

        if self.OIDC_RP_SIGN_ALGO.startswith("RS") and (
            self.OIDC_RP_IDP_SIGN_KEY is None and self.OIDC_OP_JWKS_ENDPOINT is None
        ):
            msg = "{} alg requires OIDC_RP_IDP_SIGN_KEY or OIDC_OP_JWKS_ENDPOINT to be configured."
            raise ImproperlyConfigured(msg.format(self.OIDC_RP_SIGN_ALGO))

        self.UserModel = User

    @property
    def verbose_name(self):
        """
        A human-readable name of this authentication backend.
        """
        return config.get(
            "pretix_oidc", "cas_server_name", fallback=_("Keycloack UPorto")
        )

    def authentication_url(self, request):
        """
        This method will be called to populate the URL for the authentication method's tab on the login page.
        """
        authenticate_url = reverse("plugins:pretix_oidc:oidc_authentication_init")
        authenticate_url = request.build_absolute_uri(authenticate_url)
        return authenticate_url

    # OIDC MOZILLA IMPLEMENTATION
    @staticmethod
    def get_settings(attr, *args):
        return import_from_settings(attr, *args)

    def authenticate(self, request, **kwargs):
        """Authenticates a user based on the OIDC code flow."""

        self.request = request
        if not self.request:
            return None

        state = self.request.GET.get("state")
        code = self.request.GET.get("code")
        nonce = kwargs.pop("nonce", None)

        if not code or not state:
            return None

        reverse_url = self.get_settings(
            "OIDC_AUTHENTICATION_CALLBACK_URL", "oidc_authentication_callback"
        )

        token_payload = {
            "client_id": self.OIDC_RP_CLIENT_ID,
            "client_secret": self.OIDC_RP_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": absolutify(self.request, reverse(reverse_url)),
        }

        # Get the token
        token_info = self.get_token(token_payload)
        id_token = token_info.get("id_token")
        access_token = token_info.get("access_token")

        # Validate the token
        payload = self.verify_token(id_token, nonce=nonce)

        if payload:
            self.store_tokens(access_token, id_token)
            try:
                return self.get_or_create_user(access_token, id_token, payload)
            except SuspiciousOperation as exc:
                LOGGER.warning("failed to get or create user: %s", exc)
                return None

        return None

    def get_token(self, payload):
        """Return token object as a dictionary."""

        auth = None
        if self.get_settings("OIDC_TOKEN_USE_BASIC_AUTH", False):
            # When Basic auth is defined, create the Auth Header and remove secret from payload.
            user = payload.get("client_id")
            pw = payload.get("client_secret")

            auth = HTTPBasicAuth(user, pw)
            del payload["client_secret"]

        response = requests.post(
            self.OIDC_OP_TOKEN_ENDPOINT,
            data=payload,
            auth=auth,
            verify=self.get_settings("OIDC_VERIFY_SSL", True),
            timeout=self.get_settings("OIDC_TIMEOUT", None),
            proxies=self.get_settings("OIDC_PROXY", None),
        )
        response.raise_for_status()
        return response.json()

    def verify_token(self, token, **kwargs):
        """Validate the token signature."""
        nonce = kwargs.get("nonce")

        token = force_bytes(token)
        if self.OIDC_RP_SIGN_ALGO.startswith("RS"):
            if self.OIDC_RP_IDP_SIGN_KEY is not None:
                key = self.OIDC_RP_IDP_SIGN_KEY
            else:
                key = self.retrieve_matching_jwk(token)
        else:
            key = self.OIDC_RP_CLIENT_SECRET

        payload_data = self.get_payload_data(token, key)

        # The 'token' will always be a byte string since it's
        # the result of base64.urlsafe_b64decode().
        # The payload is always the result of base64.urlsafe_b64decode().
        # In Python 3 and 2, that's always a byte string.
        # In Python3.6, the json.loads() function can accept a byte string
        # as it will automagically decode it to a unicode string before
        # deserializing https://bugs.python.org/issue17909
        payload = json.loads(payload_data.decode("utf-8"))
        token_nonce = payload.get("nonce")

        if self.get_settings("OIDC_USE_NONCE", True) and nonce != token_nonce:
            msg = "JWT Nonce verification failed."
            raise SuspiciousOperation(msg)
        return payload

    def retrieve_matching_jwk(self, token):
        """Get the signing key by exploring the JWKS endpoint of the OP."""
        response_jwks = requests.get(
            self.OIDC_OP_JWKS_ENDPOINT,
            verify=self.get_settings("OIDC_VERIFY_SSL", True),
            timeout=self.get_settings("OIDC_TIMEOUT", None),
            proxies=self.get_settings("OIDC_PROXY", None),
        )
        response_jwks.raise_for_status()
        jwks = response_jwks.json()

        # Compute the current header from the given token to find a match
        jws = JWS.from_compact(token)
        json_header = jws.signature.protected
        header = Header.json_loads(json_header)

        key = None
        for jwk in jwks["keys"]:
            if import_from_settings("OIDC_VERIFY_KID", True) and jwk[
                "kid"
            ] != smart_str(header.kid):
                continue
            if "alg" in jwk and jwk["alg"] != smart_str(header.alg):
                continue
            key = jwk
        if key is None:
            raise SuspiciousOperation("Could not find a valid JWKS.")
        return key

    def get_payload_data(self, token, key):
        """Helper method to get the payload of the JWT token."""
        if self.get_settings("OIDC_ALLOW_UNSECURED_JWT", False):
            header, payload_data, signature = token.split(b".")
            header = json.loads(smart_str(b64decode(header)))

            # If config allows unsecured JWTs check the header and return the decoded payload
            if "alg" in header and header["alg"] == "none":
                return b64decode(payload_data)

        # By default fallback to verify JWT signatures
        return self._verify_jws(token, key)

    def _verify_jws(self, payload, key):
        """Verify the given JWS payload with the given key and return the payload"""
        jws = JWS.from_compact(payload)

        try:
            alg = jws.signature.combined.alg.name
        except KeyError:
            msg = "No alg value found in header"
            raise SuspiciousOperation(msg)

        if alg != self.OIDC_RP_SIGN_ALGO:
            msg = (
                "The provider algorithm {!r} does not match the client's "
                "OIDC_RP_SIGN_ALGO.".format(alg)
            )
            raise SuspiciousOperation(msg)

        if isinstance(key, str):
            # Use smart_bytes here since the key string comes from settings.
            jwk = JWK.load(smart_bytes(key))
        else:
            # The key is a json returned from the IDP JWKS endpoint.
            jwk = JWK.from_json(key)

        if not jws.verify(jwk):
            msg = "JWS token verification failed."
            raise SuspiciousOperation(msg)

        return jws.payload

    def store_tokens(self, access_token, id_token):
        """Store OIDC tokens."""
        session = self.request.session

        if self.get_settings("OIDC_STORE_ACCESS_TOKEN", False):
            session["oidc_access_token"] = access_token

        if self.get_settings("OIDC_STORE_ID_TOKEN", False):
            session["oidc_id_token"] = id_token

    def get_or_create_user(self, access_token, id_token, payload):
        """Returns a User instance if 1 user is found. Creates a user if not found
        and configured to do so. Returns nothing if multiple users are matched."""

        user_info = self.get_userinfo(access_token, id_token, payload)

        claims_verified = self.verify_claims(user_info)
        if not claims_verified:
            msg = "Claims verification failed"
            raise SuspiciousOperation(msg)

        try:
            email = user_info["email"]
        except KeyError:
            messages.error(self.request,
                           _("Error: Email missing from keycloak roles"), )
            return None

        try:
            pk = user_info["sub"]
        except KeyError:
            messages.error(self.request,
                           _("Error: sub missing from keycloak roles"), )
            return None

        try:
            username = user_info["preferred_username"]
        except KeyError:
            username = user_info["email"]

        new_roles = set(user_info['roles']) if user_info['roles'] else set()
        if 'si-gestor-eventos-admin' in new_roles:
            is_staff = True
            new_roles.remove('si-gestor-eventos-admin')
        else:
            is_staff = False

        try:
            u = User.objects.get_or_create_for_backend(
                "keycloak_auth",
                pk,
                email,
                set_always={
                    'is_staff': is_staff,
                    'fullname': username,
                },
                set_on_creation={},
            )
        except EmailAddressTakenError:
            messages.error(
                self.request,
                _(
                    "We cannot create your user account as a user account in this system "
                    "already exists with the same email address."
                ),
            )
            return None

        api_team = self.get_settings("UP_EVENT_MANAGER_API_TEAM", "API Token - Gestor Eventos UP")
        managing_unit_team = self.get_settings("UP_EVENT_MANAGER_MANAGING_UNIT_TEAM", "Managing Unit")

        # Update Organizer Units from Roles
        prev_roles = set(Organizer.objects.filter(
            id__in=u.teams.filter(name=managing_unit_team).values_list('organizer', flat=True)
        ).values_list('slug', flat=True))

        if prev_roles != new_roles:
            for role in set(new_roles):
                # Add new roles
                obj, created = Organizer.objects.get_or_create(slug=role, defaults={'name': role})

                if not created:
                    # Check if has Manager Unit team
                    try:
                        t = Team.objects.get(organizer=obj, name=managing_unit_team)
                        t.members.add(u)
                        continue # Team is setted correctly
                    except Team.DoesNotExist:
                        pass
                    except Team.MultipleObjectsReturned:
                        pass
                    # Fix teams
                    for team in obj.teams.exclude(name=api_team):
                        team.delete()

                # Create main team that materializes a Managing Unit from Event Manager
                t = Team.objects.create(
                    organizer=obj, name=managing_unit_team,
                    all_events=True, can_create_events=True, can_change_teams=True,
                    can_manage_gift_cards=True,
                    can_change_organizer_settings=True,
                    can_change_event_settings=True,
                    can_change_items=True,
                    can_manage_customers=True,
                    can_view_orders=True, can_change_orders=True,
                    can_view_vouchers=True, can_change_vouchers=True
                )
                t.members.add(u)

            for role in prev_roles - new_roles:
                # Remove user from removed roles
                obj = Organizer.objects.get(slug=role)

                # Check if has Manager Unit team
                try:
                    t = Team.objects.get(organizer=obj, name=managing_unit_team)
                    t.members.remove(u)
                    continue  # Team is removed correctly
                except Team.DoesNotExist:
                    pass
                except Team.MultipleObjectsReturned:
                    pass
                # Fix teams
                for team in obj.teams.exclude(name=api_team):
                    team.delete()

        # Update non Mananging Unit Event Manager
        url = self.get_settings("UP_EVENT_MANAGER_API", "https://eventos.dev.uporto.pt/backoffice/api/user")
        url = f"{url}/{u.auth_backend_identifier}/"

        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/javascript',
            'Authorization': f"Token {self.get_settings('UP_EVENT_MANAGER_TOKEN', None)}"
        }
        try:
            r = requests.get(url, headers=headers)
        except requests.exceptions.RequestException as error:
            messages.error(self.request, _(f"Error API Gestor Eventos: {error}"))
            return None

        if r.status_code == 404:
            messages.error(self.request, _("Error API Gestor Eventos 404: User hash não existe no Gestor de Eventos"), )
            return None
        elif r.status_code != 200:
            messages.error(self.request, f"Error API Gestor Eventos {r.status_code} - {r.reason}")
            return None

        events = r.json()

        # Remove user from all other non Mananging Unit Event Manager
        # (By deleting them since they are single user Teams)
        u.teams.exclude(name=managing_unit_team).delete()

        for slug in events:
            # Get Event
            try:
                with scopes_disabled():
                    event = Event.objects.get(slug=slug)
            except Event.DoesNotExist:
                messages.error(self.request,
                               f"Event {slug} from Gestor de Eventos UP does not exist on Pretix")
                return None



            try:
                t = Team.objects.get(organizer=event.organizer, name=f'Manager of {slug}')
                t.members.add(u)
                continue
            except Team.MultipleObjectsReturned:
                pass
            except Team.DoesNotExist:
                pass
            t = Team.objects.create(
                organizer=event.organizer, name=f'Manager of {slug}',
                all_events=False, can_create_events=False, can_change_teams=False,
                can_manage_gift_cards=True,
                can_change_organizer_settings=False,
                can_change_event_settings=True,
                can_change_items=True,
                can_manage_customers=True,
                can_view_orders=True, can_change_orders=True,
                can_view_vouchers=True, can_change_vouchers=True
            )
            t.limit_events.add(event)
            t.members.add(u)

        return u

    def get_userinfo(self, access_token, id_token, payload):
        """Return user details dictionary. The id_token and payload are not used in
        the default implementation, but may be used when overriding this method"""

        user_response = requests.get(
            self.OIDC_OP_USER_ENDPOINT,
            headers={"Authorization": "Bearer {0}".format(access_token)},
            verify=self.get_settings("OIDC_VERIFY_SSL", True),
            timeout=self.get_settings("OIDC_TIMEOUT", None),
            proxies=self.get_settings("OIDC_PROXY", None),
        )
        user_response.raise_for_status()
        return user_response.json()

    def verify_claims(self, claims):
        """Verify the provided claims to decide if authentication should be allowed."""

        # Verify claims required by default configuration
        scopes = self.get_settings("OIDC_RP_SCOPES", "openid email")
        if "email" in scopes.split():
            return "email" in claims

        LOGGER.warning(
            "Custom OIDC_RP_SCOPES defined. "
            "You need to override `verify_claims` for custom claims verification."
        )

        return True

    def filter_users_by_claims(self, claims):
        """Return all users matching the specified email."""
        email = claims.get("email")
        if not email:
            return self.UserModel.objects.none()
        return self.UserModel.objects.filter(email__iexact=email)
