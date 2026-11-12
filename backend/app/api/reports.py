import os
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db
from app.services.report_service import ReportService

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.get("/assessment/{assessment_id}/json")
def get_json_report(assessment_id: int, db: Session = Depends(get_db)):
    try:
        data = ReportService.get_assessment_report_data(assessment_id, db)
        return JSONResponse(content=data)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/assessment/{assessment_id}/xlsx")
def download_xlsx_report(assessment_id: int, db: Session = Depends(get_db)):
    try:
        data = ReportService.get_assessment_report_data(assessment_id, db)
        filename = f"threat_model_assessment_{assessment_id}.xlsx"
        output_path = os.path.join(settings.REPORTS_DIR, filename)
        ReportService.generate_xlsx_report(data, output_path)
        return FileResponse(
            output_path,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            filename=filename
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Export error: {str(e)}")


@router.get("/assessment/{assessment_id}/docx")
def download_docx_report(assessment_id: int, db: Session = Depends(get_db)):
    try:
        data = ReportService.get_assessment_report_data(assessment_id, db)
        filename = f"threat_model_assessment_{assessment_id}.docx"
        output_path = os.path.join(settings.REPORTS_DIR, filename)
        ReportService.generate_docx_report(data, output_path)
        return FileResponse(
            output_path,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            filename=filename
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Export error: {str(e)}")


@router.get("/assessment/{assessment_id}/html")
def view_html_report(assessment_id: int, db: Session = Depends(get_db)):
    try:
        data = ReportService.get_assessment_report_data(assessment_id, db)
        filename = f"threat_model_assessment_{assessment_id}.html"
        output_path = os.path.join(settings.REPORTS_DIR, filename)
        ReportService.generate_html_report(data, output_path)
        return FileResponse(output_path, media_type="text/html", filename=filename)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report error: {str(e)}")
