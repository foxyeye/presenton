import hashlib
import ipaddress
import os
import secrets
import time

from fastapi import APIRouter, Depends, HTTPException, Request
import jwt
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import JSONResponse, RedirectResponse

from api.v1.auth.schemas import AuthCredentialsRequest, LoginCredentialsRequest, OPCEntryTokenRequest
from api.v1.auth.assets import is_app_data_path_authorized
from api.v1.auth.rate_limit import LOGIN_RATE_LIMITER, login_rate_limit_key
from api.v1.auth.principal import resolve_request_principal
from api.v1.auth.users import (
    PASSWORD_HELPER,
    get_jwt_strategy,
    read_user_from_cookie,
    serialize_user,
)
from models.sql.user import User
from services.database import get_async_session
from utils.get_env import is_disable_auth_enabled
from utils.user_config import get_user_config
from api.v1.auth.config import (
SESSION_COOKIE_NAME,
    SESSION_TTL_SECONDS,
    persist_admin_credentials,
)

OPC_ARCHIVE_CONTEXT_COOKIE_NAME = "presenton_opc_archive_context"
from api.v1.auth.token import TOKEN_ROUTER
from api.v1.auth.presenton_oauth import PRESENTON_OAUTH_ROUTER


API_V1_AUTH_ROUTER = APIRouter(prefix="/api/v1/auth", tags=["Auth"])
API_V1_AUTH_ROUTER.include_router(TOKEN_ROUTER)
API_V1_AUTH_ROUTER.include_router(PRESENTON_OAUTH_ROUTER)


@API_V1_AUTH_ROUTER.get("/runtime-config")
async def get_runtime_config(
    current_user: User | None = Depends(read_user_from_cookie),
):
    """Return the effective provider configuration to the internal web server.

    The Next.js route removes secret fields before returning this data to the
    browser. Resolving here keeps environment-backed deployments and persisted
    provider settings on the same code path as LLM requests.
    """
    if not is_disable_auth_enabled() and current_user is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return get_user_config().model_dump()


def normalize_username(username: str) -> str:
    return username.strip()


async def _account_count(session: AsyncSession) -> int:
    return int(await session.scalar(select(func.count()).select_from(User)) or 0)


def _secure_request(request: Request) -> bool:
    return (
        request.headers.get("x-forwarded-proto", "").lower() == "https"
        or request.url.scheme == "https"
    )


def _login_client_host(request: Request) -> str | None:
    peer_host = request.client.host if request.client else None
    try:
        peer_is_loopback = bool(
            peer_host and ipaddress.ip_address(peer_host).is_loopback
        )
    except ValueError:
        peer_is_loopback = False
    if peer_is_loopback:
        forwarded_host = request.headers.get("x-real-ip", "").strip()
        try:
            if forwarded_host:
                return str(ipaddress.ip_address(forwarded_host))
        except ValueError:
            pass
    return peer_host


def _set_login_cookie(response: JSONResponse, token: str, request: Request) -> None:
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=_secure_request(request),
        samesite="lax",
        path="/",
    )


def _opc_username(subject: str) -> str:
    return "opc-" + hashlib.sha256(subject.encode("utf-8")).hexdigest()


@API_V1_AUTH_ROUTER.post("/opc/exchange")
async def exchange_opc_entry_token(
    request: Request,
    session: AsyncSession = Depends(get_async_session),
):
    """Exchange an OPC-issued 60-second JWT for a Presenton cookie session."""
    form_submission = request.headers.get("content-type", "").startswith(
        "application/x-www-form-urlencoded"
    )
    try:
        if form_submission:
            form = await request.form()
            body = OPCEntryTokenRequest(token=str(form.get("token") or ""))
        else:
            body = OPCEntryTokenRequest.model_validate(await request.json())
    except (ValueError, ValidationError) as error:
        raise HTTPException(
            status_code=422,
            detail="Invalid OPC entry token request",
        ) from error
    secret = (os.getenv("PRESENTON_OPC_AUTH_SECRET") or "").strip()
    if not secret:
        raise HTTPException(status_code=503, detail="OPC entry authentication is not configured")
    try:
        claims = jwt.decode(body.token, secret, algorithms=["HS256"], audience="opc-presenton")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired OPC entry token")
    subject = claims.get("sub")
    role = claims.get("role")
    project_id = claims.get("project_id")
    presentation_id = claims.get("presentation_id")
    if not all(isinstance(value, str) and value.strip() for value in (subject, role, project_id, presentation_id)):
        raise HTTPException(status_code=401, detail="Invalid OPC entry token claims")
    if role not in {"owner", "editor", "viewer"}:
        raise HTTPException(status_code=401, detail="Invalid OPC project role")

    username = _opc_username(subject)
    user = await session.scalar(select(User).where(User.username == username))
    if user is None:
        user = User(
            username=username,
            hashed_password=PASSWORD_HELPER.hash(secrets.token_urlsafe(32)),
            is_active=True,
            is_verified=True,
            is_superuser=False,
            auth_version=1,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
    elif not user.is_active:
        raise HTTPException(status_code=403, detail="Presenton account is disabled")

    token = await get_jwt_strategy().write_token(user)
    return_to = request.query_params.get("return_to", "")
    if not (return_to.startswith("/presentation?id=") and "//" not in return_to and "&" not in return_to):
        return_to = "/"
    response = RedirectResponse(url=return_to, status_code=303) if form_submission else JSONResponse({"authenticated": True, **serialize_user(user)})
    _set_login_cookie(response, token, request)
    # Keep the OPC project context server-readable for the export flow.  The
    # original entry token lives only 60 seconds; this is a separately scoped
    # token and is never exposed to browser JavaScript.
    archive_claims = {
        "sub": subject,
        "email": claims.get("email", ""),
        "name": claims.get("name", ""),
        "project_id": project_id,
        "presentation_id": presentation_id,
        "role": role,
        "aud": "opc-presenton-archive",
        "iat": int(time.time()),
        "exp": int(time.time()) + SESSION_TTL_SECONDS,
    }
    archive_token = jwt.encode(archive_claims, secret, algorithm="HS256")
    response.set_cookie(
        OPC_ARCHIVE_CONTEXT_COOKIE_NAME,
        archive_token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=_secure_request(request),
        samesite="lax",
        path="/",
    )
    return response


@API_V1_AUTH_ROUTER.get("/status")
async def get_status(
    session: AsyncSession = Depends(get_async_session),
    user: User | None = Depends(read_user_from_cookie),
):
    if is_disable_auth_enabled():
        return {
            "configured": True,
            "authenticated": True,
            "username": "electron",
            "user_id": None,
            "role": "admin",
        }
    configured = await _account_count(session) > 0
    return {
        "configured": configured,
        "authenticated": user is not None,
        "username": user.username if user else None,
        "user_id": str(user.id) if user else None,
        "role": "admin" if user and user.is_superuser else ("user" if user else None),
    }


@API_V1_AUTH_ROUTER.get("/verify")
async def verify_session(
    request: Request,
    session: AsyncSession = Depends(get_async_session),
):
    if is_disable_auth_enabled():
        return {
            "authenticated": True,
            "username": "electron",
            "role": "admin",
            "method": "local",
        }
    principal, user = await resolve_request_principal(request, session)
    if principal is None or user is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    original_uri = request.headers.get("x-original-uri")
    if original_uri and not is_app_data_path_authorized(
        original_uri,
        user_id=principal.user_id,
        is_admin=principal.is_admin,
    ):
        raise HTTPException(status_code=403, detail="Asset access denied")
    return {
        "authenticated": True,
        **serialize_user(user),
        "method": principal.method,
    }


@API_V1_AUTH_ROUTER.post("/setup")
async def setup_credentials(
    body: AuthCredentialsRequest,
    request: Request,
    session: AsyncSession = Depends(get_async_session),
):
    if await _account_count(session):
        raise HTTPException(status_code=409, detail="Credentials already configured")

    username = normalize_username(body.username)
    if len(username) < 3:
        raise HTTPException(
            status_code=422,
            detail="Username must be at least 3 characters",
        )
    password_hash = PASSWORD_HELPER.hash(body.password)
    user = User(
        username=username,
        hashed_password=password_hash,
        is_active=True,
        is_verified=True,
        is_superuser=True,
        admin_slot="primary",
        auth_version=1,
    )
    session.add(user)
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        raise HTTPException(
            status_code=409,
            detail="Credentials already configured",
        )
    await session.commit()
    await session.refresh(user)
    persist_admin_credentials(username, password_hash)
    return {
        "configured": True,
        "authenticated": False,
        "username": user.username,
        "role": "admin",
    }


@API_V1_AUTH_ROUTER.post("/login")
async def login(
    body: LoginCredentialsRequest,
    request: Request,
    session: AsyncSession = Depends(get_async_session),
):
    if not await _account_count(session):
        raise HTTPException(status_code=428, detail="Login setup is required")
    username = normalize_username(body.username)
    rate_limit_key = login_rate_limit_key(
        _login_client_host(request),
        username,
    )
    retry_after = await LOGIN_RATE_LIMITER.retry_after(rate_limit_key)
    if retry_after is not None:
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )
    user = await session.scalar(
        select(User).where(func.lower(User.username) == username.casefold())
    )
    if user is None or not user.is_active:
        PASSWORD_HELPER.hash(body.password)
        await LOGIN_RATE_LIMITER.record_failure(rate_limit_key)
        raise HTTPException(status_code=401, detail="Unauthorized")

    verified, replacement_hash = PASSWORD_HELPER.verify_and_update(
        body.password, user.hashed_password
    )
    if not verified:
        await LOGIN_RATE_LIMITER.record_failure(rate_limit_key)
        raise HTTPException(status_code=401, detail="Unauthorized")
    if replacement_hash:
        user.hashed_password = replacement_hash
        await session.commit()
    await LOGIN_RATE_LIMITER.clear(rate_limit_key)

    token = await get_jwt_strategy().write_token(user)
    response = JSONResponse(
        {
            "configured": True,
            "authenticated": True,
            **serialize_user(user),
        }
    )
    _set_login_cookie(response, token, request)
    return response


@API_V1_AUTH_ROUTER.post("/logout")
async def logout(request: Request):
    response = JSONResponse({"success": True})
    response.delete_cookie(
        SESSION_COOKIE_NAME,
        httponly=True,
        secure=_secure_request(request),
        samesite="lax",
        path="/",
    )
    return response
