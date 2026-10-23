from __future__ import annotations

import difflib
import json
import os
import shutil
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, replace
from ipaddress import IPv4Address, IPv4Network, collapse_addresses, ip_network
from pathlib import Path
from io import StringIO
from tempfile import NamedTemporaryFile
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, Form, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
from ruamel.yaml import YAML

from .audit import AuditLogger
from .persistence import RuntimeStore
from .checks import reconcile
from .config import AppConfig, load_config, save_config
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
async def index(request: Request, subnet: str | None = None, page: int = Query(1, ge=1)):
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
            "config": config,
            "errors": errors,
            "subnets": subnets,
            "selected": selected,
            "rows": rows,
            "inventory": inventory,
            "page": page,
            "pages": pages,
            "jobs": scanner.as_dicts(),
            "user": current_user(request),
        },
    )


@router.get("/outliers", response_class=HTMLResponse)
async def outliers(request: Request, page: int = Query(1, ge=1)):
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
        "page": page, "pages": pages, "user": current_user(request),
    })


@router.get("/hosts/{host_index}", response_class=HTMLResponse)
async def host_details(request: Request, host_index: int):
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
        "host_index": host_index, "host_yaml": output.getvalue(), "user": current_user(request),
    })


@router.post("/refresh")
async def refresh(request: Request, subnet: str = Form(...), user: str = Depends(require_user)):
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
    audit.record(user, source_ip(request), "refresh", f"Refresh job {job.id}: {job.status}, {job.progress}/{job.total} addresses")
    return RedirectResponse(f"/?subnet={subnet}", status_code=303)


@router.post("/scan")
async def scan(request: Request, subnet: str = Form(...), confirm_large: bool = Form(False), user: str = Depends(require_user)):
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
