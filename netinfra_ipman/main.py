from __future__ import annotations

import asyncio
import json
import hashlib
import os
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import asdict, dataclass, replace
from ipaddress import IPv4Address, IPv4Network, collapse_addresses, ip_network
from pathlib import Path
from io import StringIO
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
from .hostwrites import HostWriteError, HostWriteService
from .models import Inventory
from .netinfra import (
    NetInfraError,
    load_inventory,
)
from .scanner import ScanManager
from .targets import ScanRequest, plan_targets
from .schedules import ScheduleManager
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
    schedules: ScheduleManager
    security: SecurityManager
    oidc: OidcClient
    hostwrites: HostWriteService


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
                schedules = ScheduleManager(config, store, scanner, audit)
                schedules.start()
                cleanup.push_async_callback(schedules.close)
                security = SecurityManager(config, store)
                oidc = OidcClient(config, store)
                cleanup.push_async_callback(oidc.close)
                application.state.services = Services(config, store, audit, scanner, schedules, security, oidc, HostWriteService(config))
                yield
        finally:
            if hasattr(application.state, "services"):
                del application.state.services

    application = FastAPI(title="NetInfra IP Manager", lifespan=lifespan)
    application.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
    application.include_router(router)
    @application.exception_handler(HostWriteError)
    async def host_write_error(request: Request, exc: HostWriteError):
        return templates.TemplateResponse(request, "write_error.html", {
            "user": request.app.state.services.security.current_user(request), "error": str(exc),
        }, status_code=exc.status_code)

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
            "scan_threshold": config.manual_scan_confirmation_threshold,
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
    data, revision = await asyncio.to_thread(host_document, request.app.state.services.config)
    hosts = data.get("Hosts")
    if not isinstance(hosts, list) or not 0 <= host_index < len(hosts):
        raise HTTPException(status_code=404, detail="Host does not exist")
    return templates.TemplateResponse(request, "host.html", {
        "host_index": host_index, "host_yaml": yaml_text(hosts[host_index]),
        "user": user, "revision": revision,
    })


@router.post("/refresh")
async def refresh(
    request: Request, subnet: str = Form(...), confirm_large: bool = Form(False),
    user: Principal = Depends(require_editor),
):
    services = request.app.state.services
    config, scanner, audit = services.config, services.scanner, services.audit
    inventory, errors = load_state(config)
    if inventory is None:
        raise HTTPException(status_code=400, detail="; ".join(errors))
    scan_request = ScanRequest("subnet", subnet, "known-only")
    try:
        plan = plan_targets(scan_request, inventory)
        if plan.total > config.manual_scan_confirmation_threshold and not confirm_large:
            return templates.TemplateResponse(request, "scan_confirm.html", {
                "user": user, "scan_request": scan_request, "total": plan.total,
                "threshold": config.manual_scan_confirmation_threshold,
            }, status_code=200)
        job = await scanner.refresh(subnet, inventory, confirmed=confirm_large)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit.record(user.subject, source_ip(request), "refresh", f"Refresh job {job.id}: {job.status}, {plan.total} addresses")
    return RedirectResponse(f"/?subnet={subnet}", status_code=303)


@router.post("/scan")
async def scan(
    request: Request,
    scope: str | None = Form(None),
    target: str = Form(""),
    mode: str = Form("full"),
    subnet: str | None = Form(None),
    confirm_large: bool = Form(False),
    user: Principal = Depends(require_editor),
):
    services = request.app.state.services
    config, scanner, audit = services.config, services.scanner, services.audit
    inventory, errors = load_state(config)
    if inventory is None:
        raise HTTPException(status_code=400, detail="; ".join(errors))
    if scope is None:
        scope, target = ("subnet", subnet) if subnet else ("all", "")
    if scope == "all":
        target = ""
    try:
        scan_request = ScanRequest(scope, target, mode)
        plan = plan_targets(scan_request, inventory)
        if plan.total > config.manual_scan_confirmation_threshold and not confirm_large:
            return templates.TemplateResponse(request, "scan_confirm.html", {
                "user": user, "scan_request": scan_request, "total": plan.total,
                "threshold": config.manual_scan_confirmation_threshold,
            }, status_code=200)
        job = scanner.start_request(scan_request, inventory, confirmed=confirm_large)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit.record(user.subject, source_ip(request), "scan", f"Started {mode} {scope} scan {job.id} for {plan.total} targets")
    return RedirectResponse("/", status_code=303)


@router.post("/scan/{job_id}/cancel")
async def cancel_scan(request: Request, job_id: str, user: Principal = Depends(require_editor)):
    services = request.app.state.services
    scanner, audit = services.scanner, services.audit
    scanner.cancel(job_id)
    audit.record(user.subject, source_ip(request), "scan_cancel", f"Cancelled scan {job_id}")
    return RedirectResponse("/", status_code=303)


@router.get("/schedules", response_class=HTMLResponse)
async def schedules_page(request: Request, user: Principal = Depends(require_admin)):
    manager = request.app.state.services.schedules
    return templates.TemplateResponse(request, "schedules.html", {
        "schedules": manager.list(), "user": user,
    })


def schedule_definition(form: Any) -> dict[str, Any]:
    allowed = {
        "csrf_token", "name", "scope", "target", "mode", "kind",
        "interval_seconds", "time", "timezone", "weekdays",
    }
    unknown = set(form.keys()) - allowed
    if unknown:
        raise ValueError("Unsupported schedule fields: " + ", ".join(sorted(unknown)))
    if any(key != "weekdays" and len(form.getlist(key)) != 1 for key in form.keys()):
        raise ValueError("Repeated schedule field")
    definition: dict[str, Any] = {
        "name": str(form.get("name", "")).strip(),
        "scope": str(form.get("scope", "all")),
        "target": str(form.get("target", "")),
        "mode": str(form.get("mode", "known-only")),
        "kind": str(form.get("kind", "interval")),
        "timezone": str(form.get("timezone", "UTC")),
    }
    if definition["kind"] == "interval":
        definition["interval_seconds"] = float(str(form.get("interval_seconds", "")))
    else:
        definition["time"] = str(form.get("time", ""))
    if definition["kind"] == "weekly":
        definition["weekdays"] = [int(value) for value in form.getlist("weekdays")]
    return definition


@router.post("/schedules")
async def schedule_create(request: Request, user: Principal = Depends(require_admin)):
    services = request.app.state.services
    form = await request.form()
    try:
        schedule = services.schedules.create(schedule_definition(form))
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    services.audit.record(user.subject, source_ip(request), "schedule.create", f"Created disabled schedule {schedule['id']}")
    return RedirectResponse("/schedules", status_code=303)


@router.post("/schedules/{schedule_id}/update")
async def schedule_update(request: Request, schedule_id: str, user: Principal = Depends(require_admin)):
    services = request.app.state.services
    form = await request.form()
    try:
        schedule = services.schedules.update(schedule_id, schedule_definition(form))
    except ValueError as exc:
        raise HTTPException(status_code=404 if str(exc) == "Schedule not found" else 400, detail=str(exc)) from exc
    services.audit.record(user.subject, source_ip(request), "schedule.update", f"Updated schedule {schedule_id}")
    return RedirectResponse("/schedules", status_code=303)


@router.post("/schedules/{schedule_id}/toggle")
async def schedule_toggle(request: Request, schedule_id: str, enabled: bool = Form(...), user: Principal = Depends(require_admin)):
    services = request.app.state.services
    try:
        schedule = services.schedules.toggle(schedule_id, enabled)
    except ValueError as exc:
        raise HTTPException(status_code=404 if str(exc) == "Schedule not found" else 400, detail=str(exc)) from exc
    services.audit.record(user.subject, source_ip(request), "schedule.toggle", f"Schedule {schedule_id} enabled={enabled}")
    return RedirectResponse("/schedules", status_code=303)


@router.post("/schedules/{schedule_id}/delete")
async def schedule_delete(request: Request, schedule_id: str, user: Principal = Depends(require_admin)):
    services = request.app.state.services
    try:
        services.schedules.delete(schedule_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    services.audit.record(user.subject, source_ip(request), "schedule.delete", f"Deleted schedule {schedule_id}")
    return RedirectResponse("/schedules", status_code=303)
def host_document(config: AppConfig) -> tuple[dict[str, Any], str]:
    # Read once: the form's revision must identify the exact document displayed.
    from .netinfra import _parse
    content = Path(config.netinfra_path).read_bytes()
    data = _parse(content)
    if not isinstance(data, dict):
        raise HostWriteError("Top-level document must be a mapping", 400)
    return data, hashlib.sha256(content).hexdigest()


def yaml_text(data: Any) -> str:
    output = StringIO()
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.dump(data, output)
    return output.getvalue()


@router.get("/hosts", response_class=HTMLResponse)
async def hosts_page(request: Request, page: int = Query(1, ge=1), user: Principal | None = Depends(require_viewer)):
    data, revision = await asyncio.to_thread(host_document, request.app.state.services.config)
    hosts = data.get("Hosts", [])
    if not isinstance(hosts, list):
        raise HostWriteError("Hosts must be a list", 400)
    pages = max(1, (len(hosts) + PAGE_SIZE - 1) // PAGE_SIZE)
    if page > pages:
        raise HTTPException(404, "Host page does not exist")
    return templates.TemplateResponse(request, "hosts.html", {
        "user": user, "hosts": list(enumerate(hosts[(page - 1) * PAGE_SIZE:page * PAGE_SIZE], (page - 1) * PAGE_SIZE)),
        "page": page, "pages": pages, "request_revision": revision,
    })


@router.get("/add", response_class=HTMLResponse)
async def add_form(request: Request, ip: str = "", user: Principal = Depends(require_editor)):
    _, revision = await asyncio.to_thread(host_document, request.app.state.services.config)
    return templates.TemplateResponse(request, "add.html", {
        "user": user, "revision": revision, "operation": "create", "host_index": "",
        "host_yaml": yaml_text({"Name": "new-host", "Records": [{"ZoneName": "example.test", "Target": ip}]}),
        "host": {}, "record": {"Target": ip},
    })


@router.get("/hosts/{host_index}/edit", response_class=HTMLResponse)
async def edit_form(request: Request, host_index: int, user: Principal = Depends(require_editor)):
    data, revision = await asyncio.to_thread(host_document, request.app.state.services.config)
    hosts = data.get("Hosts", [])
    if not isinstance(hosts, list) or not 0 <= host_index < len(hosts):
        raise HTTPException(404, "Host does not exist")
    host = hosts[host_index]
    records = host.get("Records", []) if isinstance(host, dict) else []
    return templates.TemplateResponse(request, "add.html", {
        "user": user, "revision": revision, "operation": "update", "host_index": host_index,
        "host_yaml": yaml_text(host), "host": host if isinstance(host, dict) else {},
        "record": records[0] if isinstance(records, list) and records and isinstance(records[0], dict) else {},
    })


@router.get("/import", response_class=HTMLResponse)
async def import_form(request: Request, user: Principal = Depends(require_editor)):
    _, revision = await asyncio.to_thread(host_document, request.app.state.services.config)
    return templates.TemplateResponse(request, "import.html", {
        "user": user, "revision": revision,
        "starter": yaml_text([{"Name": "new-host", "Records": [{"RRType": "no_dns", "Target": "192.0.2.1"}]}]),
    })


@router.post("/hosts/preview", response_class=HTMLResponse)
async def host_preview(request: Request, user: Principal = Depends(require_editor)):
    services = request.app.state.services
    form = await request.form()
    operation = str(form.get("operation", "create"))
    revision = str(form.get("revision", ""))
    try:
        host_index = int(str(form["host_index"])) if form.get("host_index") else None
    except ValueError:
        raise HostWriteError("Invalid host index", 400) from None
    payload = str(form.get("host_yaml", ""))
    upload = form.get("upload")
    if operation == "import" and upload is not None and getattr(upload, "filename", ""):
        try:
            payload = (await upload.read()).decode("utf-8")
        except UnicodeDecodeError:
            raise HostWriteError("Upload must be UTF-8 YAML", 400) from None
    if operation in {"create", "update"} and form.get("mode") == "common":
        data, current_revision = await asyncio.to_thread(host_document, services.config)
        if revision != current_revision:
            raise HostWriteError("Source changed. Reload the form and review again.", 409)
        if operation == "update":
            hosts = data.get("Hosts", [])
            if not isinstance(hosts, list) or host_index is None or not 0 <= host_index < len(hosts):
                raise HostWriteError("Host does not exist", 404)
            host = hosts[host_index]
            if not isinstance(host, dict):
                raise HostWriteError("Use advanced YAML to repair this host", 400)
        else:
            host = {"Name": "", "Records": [{}]}
        host["Name"] = str(form.get("name", ""))
        records = host.setdefault("Records", [])
        if not isinstance(records, list) or (records and not isinstance(records[0], dict)):
            raise HostWriteError("Use advanced YAML to repair Records", 400)
        if not records:
            records.append({})
        for field, key in (("zone_name", "ZoneName"), ("target", "Target"), ("mac", "MAC"),
                           ("comment", "Comment"), ("rrtype", "RRType"), ("source", "Source"), ("alt_hostname", "AltHostName")):
            value = str(form.get(field, ""))
            if value or key in records[0]:
                records[0][key] = value
        payload = yaml_text(host)
    preview = await asyncio.to_thread(services.hostwrites.preview, user.subject, revision, operation, payload, host_index)
    return templates.TemplateResponse(request, "preview.html", {"user": user, "preview": preview})


@router.post("/hosts/apply", response_class=HTMLResponse)
async def host_apply(request: Request, user: Principal = Depends(require_editor)):
    services = request.app.state.services
    form = await request.form()
    if set(form) - {"csrf_token", "token"}:
        raise HostWriteError("Apply accepts only the reviewed token; review changes again.", 400)
    result = await asyncio.to_thread(services.hostwrites.apply, user.subject, str(form.get("token", "")))
    services.audit.record(user.subject, source_ip(request), "write_back", "Reviewed host change saved",
                          after={"revision": result.revision, "git_status": result.git_status})
    return templates.TemplateResponse(request, "write_result.html", {"user": user, "result": result})


@router.post("/hosts/commit-retry", response_class=HTMLResponse)
async def host_commit_retry(request: Request, token: str = Form(...), user: Principal = Depends(require_editor)):
    services = request.app.state.services
    result = await asyncio.to_thread(services.hostwrites.retry_commit, user.subject, token)
    services.audit.record(user.subject, source_ip(request), "git_retry", result.git_status,
                          after={"revision": result.revision})
    return templates.TemplateResponse(request, "write_result.html", {"user": user, "result": result})


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
    services.schedules.config = config
    services.schedules.audit = replacement_audit
    services.security.config = config
    services.hostwrites.config = config
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
