from __future__ import annotations

import difflib
import hashlib
import os
import shutil
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, replace
from ipaddress import ip_network
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn

from .audit import AuditLogger
from .persistence import RuntimeStore
from .checks import check_many, resolver_available
from .config import AppConfig, load_config, save_config
from .gitops import commit_changes, ensure_clean_checkout
from .models import CheckResult, Severity
from .netinfra import (
    NetInfraError,
    append_discovered_host,
    duplicate_fqdn_ip_conflicts,
    duplicate_ip_map,
    iter_managed_records,
    iter_subnets,
    load_netinfra,
    save_netinfra,
)
from .scanner import ScanManager
from .security import (
    authenticate,
    change_password,
    current_user,
    login_response,
    logout_response,
    require_user,
)

BASE_DIR = Path(__file__).resolve().parent
router = APIRouter()
templates = Jinja2Templates(directory=BASE_DIR / "templates")


@dataclass
class Services:
    config: AppConfig
    store: RuntimeStore
    audit: AuditLogger
    scanner: ScanManager


def create_app(settings: AppConfig | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(application: FastAPI):
        config = replace(settings) if settings is not None else load_config()
        config.validate()
        store = RuntimeStore(config.sqlite_path)
        audit = None
        scanner = None
        try:
            store.initialize()
            audit = AuditLogger(config)
            scanner = ScanManager(config, store)
            application.state.services = Services(config, store, audit, scanner)
            yield
        finally:
            try:
                if scanner is not None:
                    await scanner.close()
            finally:
                if audit is not None:
                    audit.close()
                store.close()
                if hasattr(application.state, "services"):
                    del application.state.services

    application = FastAPI(title="NetInfra IP Manager", lifespan=lifespan)
    application.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
    application.include_router(router)
    return application

def source_ip(request: Request) -> str:
    config = request.app.state.services.config
    if config.reverse_proxy:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def load_state(config: AppConfig) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    data: dict[str, Any] | None = None
    try:
        data = load_netinfra(config.netinfra_path)
    except NetInfraError as exc:
        errors.append(str(exc))
    if data is not None and not resolver_available(config):
        errors.append("DNS resolver is unavailable")
    return data, errors


def row_status(record, duplicates: dict[str, int], fqdn_conflicts: set[tuple[str, str]], store: RuntimeStore) -> dict[str, Any]:
    cached = store.get(f"status:{record.ip}:{record.fqdn}")
    if cached:
        cached["severity"] = Severity(cached.get("severity", Severity.neutral.value))
        result = CheckResult(**cached)
    else:
        result = CheckResult.blank(record.ip)
    if record.ip in duplicates:
        result.severity = Severity.red
        result.reason = "Duplicate IP"
        result.tooltip = f"{duplicates[record.ip]} records define IP {record.ip}."
    if (record.fqdn.lower(), record.ip) in fqdn_conflicts:
        result.severity = Severity.red
        result.reason = "Duplicate FQDN"
        result.tooltip = f"Multiple records define {record.fqdn} for {record.ip}."
    return {"record": record, "status": result}


def subnet_rows(cidr: str, records: list, duplicates: dict[str, int], fqdn_conflicts: set[tuple[str, str]], store: RuntimeStore) -> list[dict[str, Any]]:
    by_ip = {record.ip: record for record in records}
    rows: list[dict[str, Any]] = []
    network = ip_network(cidr, strict=False)
    for ip in network.hosts():
        ip_text = str(ip)
        if ip_text in by_ip:
            rows.append(row_status(by_ip[ip_text], duplicates, fqdn_conflicts, store))
        else:
            rows.append({"record": None, "status": CheckResult.blank(ip_text)})
    return rows


@router.get("/", response_class=HTMLResponse)
async def index(request: Request, subnet: str | None = None):
    services = request.app.state.services
    config, store, scanner = services.config, services.store, services.scanner
    data, errors = load_state(config)
    records = iter_managed_records(data) if data else []
    subnets = iter_subnets(data) if data else []
    selected = subnet or (subnets[0].cidr if subnets else None)
    duplicates = duplicate_ip_map(records)
    fqdn_conflicts = duplicate_fqdn_ip_conflicts(records)
    if duplicates:
        errors.append("Duplicate IPs were found in NetInfra.yml")
    rows = subnet_rows(selected, records, duplicates, fqdn_conflicts, store) if selected else []
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "config": config,
            "errors": errors,
            "subnets": subnets,
            "selected": selected,
            "rows": rows,
            "jobs": scanner.as_dicts(),
            "user": current_user(request),
        },
    )


@router.post("/refresh")
async def refresh(request: Request, subnet: str = Form(...), user: str | None = Depends(current_user)):
    services = request.app.state.services
    config, store, audit = services.config, services.store, services.audit
    data, _ = load_state(config)
    if not data:
        return RedirectResponse("/", status_code=303)
    network = ip_network(subnet, strict=False)
    records = [record for record in iter_managed_records(data) if record.ip_address in network]
    results = await check_many(records, config)
    for record in records:
        key = f"status:{record.ip}:{record.fqdn}"
        store.set(key, results[record.ip])
    audit.record(user or "anonymous", source_ip(request), "refresh", f"Refreshed {len(records)} records in {subnet}")
    return RedirectResponse(f"/?subnet={subnet}", status_code=303)


@router.post("/scan")
async def scan(request: Request, subnet: str = Form(...), confirm_large: bool = Form(False), user: str = Depends(require_user)):
    services = request.app.state.services
    config, scanner, audit = services.config, services.scanner, services.audit
    network = ip_network(subnet, strict=False)
    if network.prefixlen < config.max_subnet_prefix:
        raise HTTPException(status_code=400, detail="Subnet too large")
    if network.prefixlen < config.large_subnet_prefix and not confirm_large:
        raise HTTPException(status_code=400, detail="Large subnet scan requires confirmation")
    data, _ = load_state(config)
    records = iter_managed_records(data or {})
    try:
        revision = hashlib.sha256(Path(config.netinfra_path).read_bytes()).hexdigest() if data is not None else None
        job = scanner.start(subnet, {record.ip for record in records}, source_revision=revision)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    audit.record(user, source_ip(request), "scan", f"Started scan {job.id} for {subnet}")
    return RedirectResponse(f"/?subnet={subnet}", status_code=303)


@router.post("/scan/{job_id}/cancel")
async def cancel_scan(request: Request, job_id: str, user: str = Depends(require_user)):
    services = request.app.state.services
    scanner, audit = services.scanner, services.audit
    scanner.cancel(job_id)
    audit.record(user, source_ip(request), "scan_cancel", f"Cancelled scan {job_id}")
    return RedirectResponse("/", status_code=303)


@router.get("/add", response_class=HTMLResponse)
async def add_form(request: Request, ip: str, user: str = Depends(require_user)):
    return templates.TemplateResponse(request, "add.html", {"ip": ip, "user": user})


@router.post("/add/preview", response_class=HTMLResponse)
async def add_preview(
    request: Request,
    name: str = Form(...),
    zone_name: str = Form(...),
    target: str = Form(...),
    mac: str = Form(""),
    comment: str = Form(""),
    user: str = Depends(require_user),
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
    user: str = Depends(require_user),
):
    services = request.app.state.services
    config, audit = services.config, services.audit
    ensure_clean_checkout(config)
    path = Path(config.netinfra_path)
    data = load_netinfra(path)
    before = path.read_text(encoding="utf-8")
    backup = path.with_name(f"{path.name}.{Path.cwd().name}.bak")
    timestamped = path.with_suffix(path.suffix + f".{__import__('datetime').datetime.utcnow().strftime('%Y%m%d%H%M%S')}.bak")
    shutil.copy2(path, timestamped)
    append_discovered_host(data, name, zone_name, target, mac or None, comment or None)
    save_netinfra(path, data)
    after = path.read_text(encoding="utf-8")
    audit.record(user, source_ip(request), "write_back", f"Added {target} to Hosts", before=before, after=after)
    relative = str(path.relative_to(config.git_repo_path)) if config.git_enabled else str(path)
    commit_changes(config, f"Add discovered host {target}", [relative])
    if backup.exists():
        backup.unlink()
    return RedirectResponse("/", status_code=303)


@router.get("/options", response_class=HTMLResponse)
async def options(request: Request):
    return templates.TemplateResponse(request, "options.html", {"config": request.app.state.services.config, "user": current_user(request)})


@router.post("/options")
async def options_save(request: Request, user: str = Depends(require_user)):
    services = request.app.state.services
    config = replace(services.config)
    form = await request.form()
    before = asdict(config)
    for key, value in form.items():
        if not hasattr(config, key):
            continue
        if key in {"sqlite_path", "config_path"}:
            if value != getattr(config, key):
                raise HTTPException(status_code=400, detail=f"{key} requires a restart; edit the configuration file")
            continue
        current = getattr(config, key)
        try:
            if isinstance(current, bool):
                setattr(config, key, value == "on")
            elif isinstance(current, int):
                setattr(config, key, int(value))
            elif isinstance(current, float):
                setattr(config, key, float(value))
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
    services.audit.record(user, source_ip(request), "config_change", "Updated options", before=before, after=asdict(config))
    services.audit.close()
    services.config = config
    services.audit = replacement_audit
    services.scanner.config = config
    return RedirectResponse("/options", status_code=303)


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"user": current_user(request)})


@router.post("/login")
async def login(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    services = request.app.state.services
    config, audit = services.config, services.audit
    user_state = authenticate(config, username, password)
    if not user_state:
        audit.record(username, source_ip(request), "login_failed", "Failed login")
        return templates.TemplateResponse(request, "login.html", {"error": "Invalid credentials"}, status_code=401)
    audit.record(username, source_ip(request), "login", "Successful login")
    redirect = RedirectResponse("/change-password" if user_state.must_change_password else "/", status_code=303)
    login_response(redirect, config, username)
    return redirect


@router.get("/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request, user: str = Depends(require_user)):
    return templates.TemplateResponse(request, "change_password.html", {"user": user})


@router.post("/change-password")
async def change_password_submit(request: Request, password: str = Form(...), user: str = Depends(require_user)):
    services = request.app.state.services
    config, audit = services.config, services.audit
    change_password(config, user, password)
    audit.record(user, source_ip(request), "password_change", "Changed password")
    return RedirectResponse("/", status_code=303)


@router.post("/logout")
async def logout(request: Request):
    audit = request.app.state.services.audit
    redirect = RedirectResponse("/", status_code=303)
    audit.record(current_user(request) or "anonymous", source_ip(request), "logout", "Logged out")
    logout_response(redirect)
    return redirect


app = create_app()


def run() -> None:
    uvicorn.run("netinfra_ipman.main:app", host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), reload=False)
