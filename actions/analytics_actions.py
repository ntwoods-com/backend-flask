"""
Advanced Analytics Actions for HRMS Dashboard

Provides pipeline statistics, hiring trends, SLA compliance metrics,
and other advanced analytics features.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, func, select

from models import AuditLog, Candidate, Requirement, SLAConfig, StepMetric
from utils import AuthContext, to_iso_utc


def candidate_pipeline_stats(data, auth: AuthContext | None, db, cfg) -> dict:
    """Get candidate counts by pipeline stage."""
    stages = [
        ("HR_REVIEW", "HR Review"),
        ("PRECALL", "Precall"),
        ("PRE_INTERVIEW", "Pre-interview"),
        ("INPERSON_TECH", "In-person Tech"),
        ("EA_TECH", "EA Tech"),
        ("FINAL_INTERVIEW", "Final Interview"),
        ("FINAL_HOLD", "Final Hold"),
        ("JOINING", "Joining"),
        ("PROBATION", "Probation"),
        ("HIRED", "Hired"),
    ]
    
    result = []
    for stage_key, stage_label in stages:
        count = db.execute(
            select(func.count(Candidate.candidateId)).where(
                and_(
                    Candidate.status == "ACTIVE",
                    Candidate.stage == stage_key
                )
            )
        ).scalar() or 0
        
        result.append({
            "stage": stage_key,
            "label": stage_label,
            "count": int(count),
        })
    
    return {"stages": result}


def dashboard_metrics(data, auth: AuthContext | None, db, cfg) -> dict:
    """Get summary metrics for dashboard."""
    now = datetime.now(timezone.utc)
    month_start = to_iso_utc(datetime(now.year, now.month, 1, tzinfo=timezone.utc))
    
    # Total active candidates
    total_candidates = db.execute(
        select(func.count(Candidate.candidateId)).where(
            Candidate.status == "ACTIVE"
        )
    ).scalar() or 0
    
    # Active requirements
    active_requirements = db.execute(
        select(func.count(Requirement.requirementId)).where(
            Requirement.status == "ACTIVE"
        )
    ).scalar() or 0
    
    # Pending approvals (candidates in FINAL_HOLD stage)
    pending_approvals = db.execute(
        select(func.count(Candidate.candidateId)).where(
            and_(
                Candidate.status == "ACTIVE",
                Candidate.stage == "FINAL_HOLD"
            )
        )
    ).scalar() or 0
    
    # This month hires
    this_month_hires = db.execute(
        select(func.count(Candidate.candidateId)).where(
            and_(
                Candidate.stage == "HIRED",
                Candidate.updatedAt >= month_start
            )
        )
    ).scalar() or 0
    
    return {
        "totalCandidates": int(total_candidates),
        "activeRequirements": int(active_requirements),
        "pendingApprovals": int(pending_approvals),
        "thisMonthHires": int(this_month_hires),
    }


def hiring_trends(data, auth: AuthContext | None, db, cfg) -> dict:
    """Get hiring trends over time."""
    period = str((data or {}).get("period") or "monthly").lower()
    if period not in {"daily", "weekly", "monthly"}:
        period = "monthly"
    date_from = str((data or {}).get("dateFrom") or "").strip()
    date_to = str((data or {}).get("dateTo") or "").strip()
    
    # Default to last 6 months
    now = datetime.now(timezone.utc)
    if not date_from:
        date_from = to_iso_utc(now - timedelta(days=180))
    if not date_to:
        date_to = to_iso_utc(now)
    
    # Get audit logs for HIRED transitions
    logs = db.execute(
        select(AuditLog).where(
            and_(
                AuditLog.action == "CANDIDATE_STAGE_UPDATE",
                AuditLog.toState == "HIRED",
                AuditLog.at >= date_from,
                AuditLog.at <= date_to
            )
        ).order_by(AuditLog.at.asc())
    ).scalars().all()
    
    # Group by period
    trend_data = {}
    for log in logs:
        try:
            dt = datetime.fromisoformat(log.at.replace("Z", "+00:00"))
            if period == "daily":
                key = dt.strftime("%Y-%m-%d")
            elif period == "weekly":
                key = dt.strftime("%Y-W%U")
            else:
                key = dt.strftime("%Y-%m")
            
            trend_data[key] = trend_data.get(key, 0) + 1
        except Exception:
            continue
    
    result = [{"period": k, "count": v} for k, v in sorted(trend_data.items())]
    return {"trends": result, "period": period}


def source_distribution(data, auth: AuthContext | None, db, cfg) -> dict:
    """Get candidate source distribution."""
    date_from = str((data or {}).get("dateFrom") or "").strip()
    date_to = str((data or {}).get("dateTo") or "").strip()

    q = select(Candidate.source, func.count(Candidate.candidateId).label("count")).where(Candidate.status == "ACTIVE")
    if date_from:
        q = q.where(Candidate.createdAt >= date_from)
    if date_to:
        q = q.where(Candidate.createdAt <= date_to)

    sources = db.execute(q.group_by(Candidate.source)).all()
    
    result = []
    color_map = {
        "JOB_PORTAL": "blue",
        "REFERRAL": "green",
        "WALK_IN": "orange",
        "CAMPUS": "purple",
        "AGENCY": "red",
    }
    
    for source, count in sources:
        source_key = str(source or "OTHER").upper()
        result.append({
            "source": source_key,
            "label": source_key.replace("_", " ").title(),
            "count": int(count),
            "color": color_map.get(source_key, "gray"),
        })
    
    return {"sources": result}


def sla_compliance_metrics(data, auth: AuthContext | None, db, cfg) -> dict:
    """Get SLA compliance metrics by stage."""
    # Get SLA configs
    sla_configs = db.execute(select(SLAConfig).where(SLAConfig.enabled == True)).scalars().all()
    sla_map = {s.stepName: s.plannedMinutes for s in sla_configs}
    
    # Get step metrics
    stages = ["HR_REVIEW", "PRECALL", "PRE_INTERVIEW", "INPERSON_TECH", "FINAL_INTERVIEW", "JOINING"]
    
    result = []
    for stage in stages:
        planned_minutes = int(sla_map.get(stage, 60) or 0)
        if planned_minutes <= 0:
            planned_minutes = 60  # Default 60 mins
        
        # Get metrics for this stage
        metrics = (
            db.execute(
                select(StepMetric)
                .where(and_(StepMetric.stepName == stage, StepMetric.actualMinutes.isnot(None)))
                .order_by(StepMetric.createdAt.desc())
                .limit(100)
            )
            .scalars()
            .all()
        )
        
        if not metrics:
            result.append({
                "stage": stage,
                "label": stage.replace("_", " ").title(),
                "compliance": 100,
                "avgMinutes": 0,
                "totalCount": 0,
            })
            continue
        
        compliant_count = 0
        total_minutes = 0
        total_count = 0
        
        for m in metrics:
            if m.actualMinutes is None:
                continue
            total_count += 1
            actual = int(m.actualMinutes or 0)
            total_minutes += actual

            planned_eff = int(m.plannedMinutes or 0) if int(m.plannedMinutes or 0) > 0 else planned_minutes
            if planned_eff <= 0 or actual <= planned_eff:
                compliant_count += 1
        
        compliance = (compliant_count / total_count * 100) if total_count else 100
        avg_minutes = total_minutes / total_count if total_count else 0
        
        result.append({
            "stage": stage,
            "label": stage.replace("_", " ").title(),
            "compliance": round(compliance, 1),
            "avgMinutes": round(avg_minutes, 1),
            "plannedMinutes": planned_minutes,
            "totalCount": total_count,
        })
    
    return {"metrics": result}


def recent_activity(data, auth: AuthContext | None, db, cfg) -> dict:
    """Get recent activity from audit log."""
    try:
        limit = int((data or {}).get("limit") or 20)
    except Exception:
        limit = 20
    limit = max(1, min(100, limit))
    entity_type = str((data or {}).get("entityType") or "").strip() or None
    
    q = select(AuditLog).order_by(AuditLog.at.desc()).limit(limit)
    
    if entity_type:
        q = q.where(AuditLog.entityType == entity_type)
    
    logs = db.execute(q).scalars().all()
    
    activities = []
    for log in logs:
        activity_type = "UPDATE"
        if "CREATE" in log.action or "ADD" in log.action:
            activity_type = "CREATE"
        elif "DELETE" in log.action or "REMOVE" in log.action:
            activity_type = "DELETE"
        elif "REJECT" in log.action or "FAIL" in log.action:
            activity_type = "REJECTION"
        elif "APPROVE" in log.action:
            activity_type = "APPROVAL"
        elif "HIRE" in log.action or log.toState == "HIRED":
            activity_type = "HIRE"
        elif log.fromState and log.toState:
            activity_type = "STATUS_CHANGE"
        
        activities.append({
            "id": log.logId,
            "type": activity_type,
            "title": log.action.replace("_", " ").title(),
            "description": log.remark or f"{log.entityType}: {log.entityId}",
            "timestamp": log.at,
            "metadata": {
                "from": log.fromState or None,
                "to": log.toState or None,
                "actor": log.actorUserId or "System",
            },
        })
    
    return {"activities": activities}


def export_analytics_report(data, auth: AuthContext | None, db, cfg) -> dict:
    """Generate analytics report for export."""
    report_type = str((data or {}).get("reportType") or "pipeline").lower()
    format_type = str((data or {}).get("format") or "excel").lower()
    
    # For now, just return a placeholder
    # In production, this would generate actual files
    return {
        "status": "pending",
        "reportType": report_type,
        "format": format_type,
        "message": "Report generation queued. You will be notified when ready.",
    }
