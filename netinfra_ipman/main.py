from __future__ import annotations

import asyncio
import difflib
import json
import hashlib
import os
import shutil
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import asdict, dataclass, replace
from ipaddress import IPv4Address, IPv4Network, collapse_addresses, ip_network
from pathlib import Path
from io import StringIO
from tempfile import NamedTemporaryFile
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
from ruamel.yaml import YAML

from .audit import AuditLogger, source_ip as audit_source_ip
from .persistence import RuntimeStore
from .checks import reconcile
from .config import AppConfig, SECRET_FIELDS, load_config, public_settings, save_config
from .gitops import commit_changes, ensure_clean_checkout
from .models import Inventory
from .netinfra import (
    NetInfraError,
    append_discovered_host,
    load_netinfra,
    load_inventory,
    save_netinfra,
)
from .scanner import ScanManager
from .oidc import OidcClient, OIDCError
from .security import (
    Principal,
    SecurityManager,
    authenticate,
    change_password,
    require_admin,
    require_editor,
    require_user,
    require_viewer,
    verify_csrf,
)

BASE_DIR = Path(__file__).resolve().parent
router = APIRouter(dependencies=[Depends(verify_csrf)])
templates = Jinja2Templates(directory=BASE_DIR / "templates")

templates.env.globals["csrf_token"] = lambda request: request.app.state.services.security.csrf_token(request)

RESTART_FIELDS = frozenset({
    "config_path", "sqlite_path", "admin_file", "session_cookie_secure",
    "oidc_enabled", "oidc_issuer", "oidc_client_id", "oidc_redirect_uri",
    "oidc_groups_claim", "oidc_roles_claim", "oidc_group_role_map", "oidc_claim_role_map",
    "trusted_proxies",
})


def readonly_settings(config: AppConfig) -> frozenset[str]:
    actual = asdict(config)
    return RESTART_FIELDS | frozenset(
        key for key, value in public_settings(config).items() if key not in actual or actual[key] != value
    )

@dataclass
class Services:
    config: AppConfig
    store: RuntimeStore
    audit: AuditLogger
    scanner: ScanManager
    security: SecurityManager
    oidc: OidcClient


def create_app(settings: AppConfig | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(application: FastAPI):
        config = replace(settings) if settings is not None else load_config()
        config.validate()
        try:
            async with AsyncExitStack() as cleanup:
                store = RuntimeStore(config.sqlite_path)
                store.initialize()
                cleanup.callback(store.close)
                audit = AuditLogger(config)
                def close_audit() -> None:
                    # Live settings replace the logger; close the current one.
                    services = getattr(application.state, "services", None)
                    (services.audit if services is not None else audit).close()
                cleanup.callback(close_audit)
                scanner = ScanManager(config, store)
                cleanup.push_async_callback(scanner.close)
                security = SecurityManager(config, store)
                oidc = OidcClient(config, store)
                cleanup.push_async_callback(oidc.close)
                application.state.services = Services(config, store, audit, scanner, security, oidc)
                yield
        finally:
            if hasattr(application.state, "services"):
                del application.state.services

    application = FastAPI(title="NetInfra IP Manager", lifespan=lifespan)
    application.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
    application.include_router(router)

    @application.exception_handler(401)
    async def unauthenticated(request: Request, exc: HTTPException):
        if request.method in {"GET", "HEAD"} and "text/html" in request.headers.get("accept", ""):
            return RedirectResponse("/login", status_code=303)
        return JSONResponse({"detail": exc.detail}, status_code=401, headers=exc.headers)

    @application.middleware("http")
    async def audit_requests(request: Request, call_next):
        services = request.app.state.services
        user = services.security.current_user(request)
        actor = user.subject if user else "anonymous"
        client_ip = audit_source_ip(request, services.config)
        try:
            response = await call_next(request)
        except Exception as exc:
            pattern = getattr(request.scope.get("route"), "path", "<unmatched>")
            services.audit.record(actor, client_ip, "request_failed",
                                  f"{request.method} {pattern}: {type(exc).__name__}")
            raise
        if request.method not in {"GET", "HEAD", "OPTIONS"} or response.status_code >= 400:
            pattern = getattr(request.scope.get("route"), "path", "<unmatched>")
            services.audit.record(actor, client_ip, "request_outcome",
                                  f"{request.method} {pattern}: HTTP {response.status_code}")
        if not request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response
    return application

def source_ip(request: Request) -> str:
    return audit_source_ip(request, request.app.state.services.config)


def load_state(config: AppConfig) -> tuple[Inventory | None, list[str]]:
    try:
        return load_inventory(config.netinfra_path), []
    except NetInfraError as exc:
        return None, [str(exc)]


def declared_scope(cidr: str, inventory: Inventory) -> IPv4Network:
    try:
        network = ip_network(cidr, strict=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid IPv4 subnet") from exc
    declared = collapse_addresses(ip_network(subnet.cidr) for subnet in inventory.subnets)
    if network.version != 4 or not any(network.subnet_of(parent) for parent in declared):
        raise HTTPException(status_code=400, detail="Targets must be within declared IPv4 subnets")
    return network


def address_row(ip: str, inventory: Inventory, config: AppConfig, store: RuntimeStore) -> dict[str, Any]:
    group = inventory.groups.get(ip)
    observation = store.get(f"observation:{ip}")
    if group is not None:
        status = reconcile(group, inventory, config, observation)
    else:
        responding = observation is not None and observation.get("ping_ok") is True
        status = {
            "ip": ip, "severity": "yellow" if responding else "neutral",
            "reason": "Undocumented responder" if responding else "Unchecked",
            "tooltip": "No eligible file assignment. Silence is not evidence that this IP is free.",
            "checked_at": observation.get("checked_at", "") if observation else "",
            "ping_ok": observation.get("ping_ok") if observation else None,
            "mac_found": None, "mac_ok": None, "dns_checks": [],
            "source_revision": observation.get("source_revision") if observation else None,
        }
    return {"group": group, "status": status}


PAGE_SIZE = 256


def subnet_rows(cidr: str, inventory: Inventory, config: AppConfig, store: RuntimeStore, page: int) -> tuple[list[dict[str, Any]], int]:
    network = declared_scope(cidr, inventory)
    total = network.num_addresses if network.prefixlen >= 31 else network.num_addresses - 2
    pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    if page > pages:
        raise HTTPException(status_code=404, detail="Address page does not exist")
    first = int(network.network_address) + (0 if network.prefixlen >= 31 else 1)
    start = (page - 1) * PAGE_SIZE
    rows = [
        address_row(str(IPv4Address(first + offset)), inventory, config, store)
        for offset in range(start, min(start + PAGE_SIZE, total))
    ]
    return rows, pages


@router.get("/", response_class=HTMLResponse)
async def index(request: Request, subnet: str | None = None, page: int = Query(1, ge=1), user: Principal | None = Depends(require_viewer)):
    services = request.app.state.services
    config, store, scanner = services.config, services.store, services.scanner
    inventory, errors = load_state(config)
    subnets = inventory.subnets if inventory else []
    selected = subnet or (subnets[0].cidr if subnets else None)
    rows, pages = subnet_rows(selected, inventory, config, store, page) if selected and inventory else ([], 1)
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "errors": errors,
            "subnets": subnets,
            "selected": selected,
            "rows": rows,
            "inventory": inventory,
            "page": page,
            "pages": pages,
            "jobs": scanner.as_dicts(),
            "user": user,
        },
    )


@router.get("/outliers", response_class=HTMLResponse)
async def outliers(request: Request, page: int = Query(1, ge=1), user: Principal | None = Depends(require_viewer)):
    services = request.app.state.services
    inventory, errors = load_state(services.config)
    groups = inventory.outliers if inventory else []
    pages = max(1, (len(groups) + PAGE_SIZE - 1) // PAGE_SIZE)
    if page > pages:
        raise HTTPException(status_code=404, detail="Outlier page does not exist")
    rows = [
        address_row(group.ip, inventory, services.config, services.store)
        for group in groups[(page - 1) * PAGE_SIZE:page * PAGE_SIZE]
    ]
    return templates.TemplateResponse(request, "outliers.html", {
        "inventory": inventory, "errors": errors, "rows": rows,
        "page": page, "pages": pages, "user": user,
    })


@router.get("/hosts/{host_index}", response_class=HTMLResponse)
async def host_details(request: Request, host_index: int, user: Principal | None = Depends(require_viewer)):
    try:
        data = load_netinfra(request.app.state.services.config.netinfra_path)
    except NetInfraError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    hosts = data.get("Hosts")
    if not isinstance(hosts, list) or not 0 <= host_index < len(hosts):
        raise HTTPException(status_code=404, detail="Host does not exist")
    output = StringIO()
    YAML().dump(hosts[host_index], output)
    return templates.TemplateResponse(request, "host.html", {
        "host_index": host_index, "host_yaml": output.getvalue(), "user": user,
    })


@router.post("/refresh")
async def refresh(request: Request, subnet: str = Form(...), user: Principal = Depends(require_editor)):
    services = request.app.state.services
    config, scanner, audit = services.config, services.scanner, services.audit
    inventory, errors = load_state(config)
    if inventory is None:
        raise HTTPException(status_code=400, detail="; ".join(errors))
    network = declared_scope(subnet, inventory)
    try:
        job = await scanner.refresh(str(network), inventory)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    audit.record(user.subject, source_ip(request), "refresh", f"Refresh job {job.id}: {job.status}, {job.progress}/{job.total} addresses")
    return RedirectResponse(f"/?subnet={subnet}", status_code=303)


@router.post("/scan")
async def scan(request: Request, subnet: str = Form(...), confirm_large: bool = Form(False), user: Principal = Depends(require_editor)):
    services = request.app.state.services
    config, scanner, audit = services.config, services.scanner, services.audit
    inventory, errors = load_state(config)
    if inventory is None:
        raise HTTPException(status_code=400, detail="; ".join(errors))
    network = declared_scope(subnet, inventory)
    if network.prefixlen < config.max_subnet_prefix:
        raise HTTPException(status_code=400, detail="Subnet too large")
    if network.prefixlen < config.large_subnet_prefix and not confirm_large:
        raise HTTPException(status_code=400, detail="Large subnet scan requires confirmation")
    try:
        job = scanner.start(str(network), inventory)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    audit.record(user.subject, source_ip(request), "scan", f"Started scan {job.id} for {subnet}")
    return RedirectResponse(f"/?subnet={subnet}", status_code=303)


@router.post("/scan/{job_id}/cancel")
async def cancel_scan(request: Request, job_id: str, user: Principal = Depends(require_editor)):
    services = request.app.state.services
    scanner, audit = services.scanner, services.audit
    scanner.cancel(job_id)
    audit.record(user.subject, source_ip(request), "scan_cancel", f"Cancelled scan {job_id}")
    return RedirectResponse("/", status_code=303)


@router.get("/add", response_class=HTMLResponse)
async def add_form(request: Request, ip: str, user: Principal = Depends(require_editor)):
    return templates.TemplateResponse(request, "add.html", {"ip": ip, "user": user})


@router.post("/add/preview", response_class=HTMLResponse)
async def add_preview(
    request: Request,
    name: str = Form(...),
    zone_name: str = Form(...),
    target: str = Form(...),
    mac: str = Form(""),
    comment: str = Form(""),
    user: Principal = Depends(require_editor),
):
    config = request.app.state.services.config
    data = load_netinfra(config.netinfra_path)
    before = Path(config.netinfra_path).read_text(encoding="utf-8")
    append_discovered_host(data, name, zone_name, target, mac or None, comment or None)
    with NamedTemporaryFile("w+", encoding="utf-8", delete=False) as temp:
        temp_path = Path(temp.name)
    save_netinfra(temp_path, data)
    after = temp_path.read_text(encoding="utf-8")
    temp_path.unlink(missing_ok=True)
    diff = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile="current", tofile="proposed"))
    return templates.TemplateResponse(
        request,
        "preview.html",
        {"diff": diff, "form": {"name": name, "zone_name": zone_name, "target": target, "mac": mac, "comment": comment}, "user": user},
    )


@router.post("/add/commit")
async def add_commit(
    request: Request,
    name: str = Form(...),
    zone_name: str = Form(...),
    target: str = Form(...),
    mac: str = Form(""),
    comment: str = Form(""),
    user: Principal = Depends(require_editor),
):
    services = request.app.state.services
    config, audit = services.config, services.audit
    ensure_clean_checkout(config)
    path = Path(config.netinfra_path)
    data = load_netinfra(path)
    before = path.read_bytes()
    backup = path.with_name(f"{path.name}.{Path.cwd().name}.bak")
    timestamped = path.with_suffix(path.suffix + f".{__import__('datetime').datetime.utcnow().strftime('%Y%m%d%H%M%S')}.bak")
    shutil.copy2(path, timestamped)
    append_discovered_host(data, name, zone_name, target, mac or None, comment or None)
    save_netinfra(path, data)
    after = path.read_bytes()
    audit.record(user.subject, source_ip(request), "write_back", f"Added {target} to Hosts",
                 before={"revision": hashlib.sha256(before).hexdigest()},
                 after={"revision": hashlib.sha256(after).hexdigest()})
    relative = str(path.relative_to(config.git_repo_path)) if config.git_enabled else str(path)
    commit_changes(config, f"Add discovered host {target}", [relative])
    if backup.exists():
        backup.unlink()
    return RedirectResponse("/", status_code=303)


@router.get("/options", response_class=HTMLResponse)
async def options(request: Request, user: Principal = Depends(require_admin)):
    services = request.app.state.services
    return templates.TemplateResponse(request, "options.html", {
        "settings": public_settings(services.config), "secret_fields": SECRET_FIELDS,
        "restart_fields": readonly_settings(services.config), "user": user,
    })


@router.post("/options")
async def options_save(request: Request, user: Principal = Depends(require_admin)):
    services = request.app.state.services
    config = replace(services.config)
    form = await request.form()
    before = public_settings(config)
    readonly = readonly_settings(config)
    for key in form:
        if key == "csrf_token":
            continue
        if key in SECRET_FIELDS:
            raise HTTPException(status_code=400, detail="Secrets must be changed in the protected configuration file")
        if key not in AppConfig.__dataclass_fields__ or len(form.getlist(key)) != 1:
            raise HTTPException(status_code=400, detail="Unknown or repeated settings field")
        if key in readonly:
            if key not in before or str(form[key]) != str(getattr(config, key)) or key not in RESTART_FIELDS:
                raise HTTPException(status_code=400, detail="Protected settings require editing the configuration file and restarting")
    for key, current in asdict(config).items():
        if key in SECRET_FIELDS or key in readonly:
            continue
        if key not in form:
            continue
        value = form[key]
        try:
            if isinstance(current, bool):
                if value not in {"on", "off"}:
                    raise ValueError("Invalid boolean")
                setattr(config, key, value == "on")
            elif isinstance(current, int):
                setattr(config, key, int(value))
            elif isinstance(current, float):
                setattr(config, key, float(value))
            elif isinstance(current, dict):
                setattr(config, key, json.loads(str(value)))
            elif isinstance(current, list):
                setattr(config, key, [item.strip() for item in str(value).split(",") if item.strip()])
            else:
                setattr(config, key, str(value))
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"Invalid value for {key}") from exc
    try:
        config.validate()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    replacement_audit = AuditLogger(config)
    try:
        save_config(config)
    except Exception:
        replacement_audit.close()
        raise
    target_audit = replacement_audit if config.audit_to_file or config.audit_to_syslog else services.audit
    target_audit.record(user.subject, source_ip(request), "config_change", "Updated options",
                          before=before, after=public_settings(config))
    services.audit.close()
    services.config = config
    services.audit = replacement_audit
    services.scanner.config = config
    services.security.config = config
    return RedirectResponse("/options", status_code=303)


@router.get("/audit", response_class=HTMLResponse)
async def audit_page(request: Request, user: Principal = Depends(require_admin)):
    services = request.app.state.services
    return templates.TemplateResponse(request, "audit.html", {
        "events": services.audit.recent_events(), "file_logging": services.config.audit_to_file, "user": user,
    })


def render_login(request: Request, error: str | None = None, status_code: int = 200):
    services = request.app.state.services
    token, new_cookie = services.security.prepare_login(request)
    response = templates.TemplateResponse(request, "login.html", {
        "user": services.security.current_user(request), "error": error,
        "login_csrf": token, "oidc_enabled": services.config.oidc_enabled,
    }, status_code=status_code)
    if new_cookie is not None:
        services.security.set_cookie(response, new_cookie)
    return response


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return render_login(request)


@router.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    services = request.app.state.services
    try:
        principal = await asyncio.to_thread(authenticate, services.config, username, password)
    except HTTPException:
        services.audit.record("anonymous", source_ip(request), "login_failed", "Emergency administrator login denied")
        return render_login(request, "Login is temporarily unavailable.", status_code=423)
    if principal is None:
        services.audit.record("anonymous", source_ip(request), "login_failed", "Emergency administrator login denied")
        return render_login(request, "Invalid credentials", status_code=401)
    response = RedirectResponse("/change-password" if principal.must_change_password else "/", status_code=303)
    services.security.revoke(request)
    services.security.login(response, principal)
    services.audit.record(principal.subject, source_ip(request), "login", "Emergency administrator login succeeded")
    return response


@router.post("/oidc/login")
async def oidc_login(request: Request):
    services = request.app.state.services
    if not services.config.oidc_enabled:
        raise HTTPException(status_code=404, detail="OIDC is disabled")
    binding = services.security.browser_binding(request)
    if binding is None:
        raise HTTPException(status_code=403, detail="Start sign-in from the login page")
    try:
        url = await services.oidc.begin(binding)
    except OIDCError:
        services.audit.record("anonymous", source_ip(request), "oidc_failed", "OIDC sign-in could not start")
        return render_login(request, "OIDC sign-in is unavailable.", status_code=503)
    return RedirectResponse(url, status_code=303)


@router.get("/oidc/callback")
async def oidc_callback(request: Request, state: str = "", code: str = ""):
    services = request.app.state.services
    if not services.config.oidc_enabled:
        raise HTTPException(status_code=404, detail="OIDC is disabled")
    try:
        principal = await services.oidc.complete(state, code, services.security.browser_binding(request) or "")
    except OIDCError:
        services.audit.record("anonymous", source_ip(request), "oidc_failed", "OIDC callback rejected")
        return render_login(request, "OIDC sign-in failed. Start again from this page.", status_code=401)
    response = RedirectResponse("/", status_code=303)
    services.security.revoke(request)
    services.security.login(response, principal)
    services.audit.record(principal.subject, source_ip(request), "login", "OIDC login succeeded")
    return response


@router.get("/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request, user: Principal = Depends(require_user)):
    if user.auth_method != "local":
        raise HTTPException(status_code=403, detail="Manage your SSO password at the identity provider")
    return templates.TemplateResponse(request, "change_password.html", {"user": user})


@router.post("/change-password")
async def change_password_submit(
    request: Request, password: str = Form(...), current_password: str = Form(...),
    confirm_password: str = Form(...), user: Principal = Depends(require_user),
):
    services = request.app.state.services
    if user.auth_method != "local":
        raise HTTPException(status_code=403, detail="Manage your SSO password at the identity provider")
    if password != confirm_password:
        return templates.TemplateResponse(request, "change_password.html",
                                          {"user": user, "error": "New passwords do not match."}, status_code=400)
    try:
        principal = await asyncio.to_thread(change_password, services.config, user, current_password, password)
    except (ValueError, HTTPException):
        services.audit.record(user.subject, source_ip(request), "password_change_failed", "Password change rejected")
        return templates.TemplateResponse(request, "change_password.html", {
            "user": user, "error": "Password change failed. Check your current password and use at least 12 characters.",
        }, status_code=400)
    response = RedirectResponse("/", status_code=303)
    services.security.revoke(request)
    services.security.login(response, principal)
    services.audit.record(user.subject, source_ip(request), "password_change", "Emergency administrator password changed")
    return response


@router.post("/logout")
async def logout(request: Request, user: Principal = Depends(require_user)):
    services = request.app.state.services
    response = RedirectResponse("/login", status_code=303)
    services.security.logout(request, response)
    services.audit.record(user.subject, source_ip(request), "logout", "Session revoked")
    return response


app = create_app()


def run() -> None:
    uvicorn.run("netinfra_ipman.main:app", host="0.0.0.0", port=int(os.environ.get("PORT", "8000")),
                reload=False, proxy_headers=False, access_log=False)
