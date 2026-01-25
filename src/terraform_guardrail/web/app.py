from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from terraform_guardrail.scanner.scan import scan_path

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"


def create_app() -> FastAPI:
    app = FastAPI(title="Terraform Guardrail MCP (TerraGuard)")
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            "index.html", {"request": request, "report": None, "error": None}
        )

    @app.post("/scan", response_class=HTMLResponse)
    async def scan(
        request: Request, tf_file: Annotated[UploadFile, File(...)]
    ) -> HTMLResponse:
        if not tf_file.filename:
            return templates.TemplateResponse(
                "index.html", {"request": request, "report": None, "error": "No file uploaded."}
            )
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir) / tf_file.filename
            tmp_path.write_bytes(await tf_file.read())
            try:
                report = scan_path(tmp_path)
            except Exception as exc:  # noqa: BLE001
                return templates.TemplateResponse(
                    "index.html", {"request": request, "report": None, "error": str(exc)}
                )
        return templates.TemplateResponse(
            "index.html", {"request": request, "report": report, "error": None}
        )

    return app
