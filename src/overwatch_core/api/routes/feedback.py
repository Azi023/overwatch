"""
Feedback API endpoints for human validation.

This is critical for the learning loop - humans mark findings as
true positive or false positive, creating ground truth for training.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum

from ..persistence.database import get_db
from ..persistence.models import FeedbackModel, ObservationModel, Finding
from ..learning.observation import Observation, ObservationType
from ..learning.observation_store import ObservationStore

router = APIRouter(prefix="/api/v1/feedback", tags=["feedback"])


# ============== Schemas ==============

class FeedbackType(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"
    CORRECTION = "correction"


class FeedbackCreate(BaseModel):
    """Schema for creating feedback."""
    observation_id: Optional[str] = Field(None, description="ID of the observation to provide feedback on")
    finding_id: Optional[int] = Field(None, description="ID of the finding to provide feedback on")
    feedback_type: FeedbackType = Field(..., description="Type of feedback")
    feedback_value: dict = Field(default_factory=dict, description="Additional feedback details")
    source: str = Field(default="api", description="Source of feedback (ui, api, automated)")
    notes: Optional[str] = Field(None, description="Human notes about the feedback")
    
    class Config:
        json_schema_extra = {
            "example": {
                "observation_id": "abc123def456",
                "feedback_type": "false_positive",
                "feedback_value": {"reason": "Test environment", "confidence": 0.95},
                "source": "ui",
                "notes": "This was a false positive because it was in our test environment"
            }
        }


class FeedbackResponse(BaseModel):
    """Schema for feedback response."""
    id: int
    observation_id: Optional[str]
    finding_id: Optional[int]
    feedback_type: str
    feedback_value: dict
    source: str
    created_at: datetime
    
    class Config:
        from_attributes = True


class ObservationSummary(BaseModel):
    """Simplified observation for API response."""
    id: str
    observation_type: str
    timestamp: datetime
    target_id: int
    scan_job_id: int
    predictions: dict
    has_ground_truth: bool
    
    class Config:
        from_attributes = True


class ObservationDetail(BaseModel):
    """Detailed observation for API response."""
    id: str
    observation_type: str
    timestamp: datetime
    target_id: int
    scan_job_id: int
    raw_data: dict
    features: dict
    predictions: dict
    ground_truth: Optional[dict]
    ground_truth_source: Optional[str]
    
    class Config:
        from_attributes = True


# ============== Endpoints ==============

@router.post("/", response_model=FeedbackResponse, status_code=status.HTTP_201_CREATED)
async def create_feedback(
    feedback: FeedbackCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Submit feedback on an observation or finding.
    
    This is the primary endpoint for the learning loop.
    When humans validate findings, their feedback becomes
    ground truth for training ML models.
    """
    # Validate that at least one ID is provided
    if not feedback.observation_id and not feedback.finding_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either observation_id or finding_id must be provided"
        )
    
    # Verify observation exists if provided
    if feedback.observation_id:
        result = await db.execute(
            select(ObservationModel).where(ObservationModel.id == feedback.observation_id)
        )
        observation = result.scalar_one_or_none()
        
        if not observation:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Observation {feedback.observation_id} not found"
            )
        
        # Update observation's ground truth
        observation.ground_truth = {
            "feedback_type": feedback.feedback_type.value,
            "is_true_positive": feedback.feedback_type == FeedbackType.TRUE_POSITIVE,
            **feedback.feedback_value
        }
        observation.ground_truth_source = feedback.source
        observation.ground_truth_timestamp = datetime.utcnow()
    
    # Verify finding exists if provided
    if feedback.finding_id:
        result = await db.execute(
            select(Finding).where(Finding.id == feedback.finding_id)
        )
        finding = result.scalar_one_or_none()
        
        if not finding:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Finding {feedback.finding_id} not found"
            )
        
        # Update finding validation status
        finding.validated = True
        finding.validation_result = feedback.feedback_type.value
    
    # Create feedback record
    db_feedback = FeedbackModel(
        observation_id=feedback.observation_id,
        finding_id=feedback.finding_id,
        feedback_type=feedback.feedback_type.value,
        feedback_value={
            **feedback.feedback_value,
            "notes": feedback.notes
        },
        source=feedback.source,
        created_at=datetime.utcnow()
    )
    
    db.add(db_feedback)
    await db.commit()
    await db.refresh(db_feedback)
    
    return db_feedback


@router.get("/", response_model=List[FeedbackResponse])
async def list_feedback(
    observation_id: Optional[str] = None,
    finding_id: Optional[int] = None,
    feedback_type: Optional[FeedbackType] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    """
    List feedback records with optional filtering.
    """
    query = select(FeedbackModel)
    
    if observation_id:
        query = query.where(FeedbackModel.observation_id == observation_id)
    if finding_id:
        query = query.where(FeedbackModel.finding_id == finding_id)
    if feedback_type:
        query = query.where(FeedbackModel.feedback_type == feedback_type.value)
    
    query = query.offset(skip).limit(limit).order_by(FeedbackModel.created_at.desc())
    
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/observations/{scan_job_id}", response_model=List[ObservationSummary])
async def get_observations_for_scan(
    scan_job_id: int,
    db: AsyncSession = Depends(get_db)
):
    """
    Get all observations for a specific scan job.
    
    Useful for reviewing what the system observed during a scan.
    """
    observation_store = ObservationStore(db)
    observations = await observation_store.get_by_scan_job(scan_job_id)
    
    return [
        ObservationSummary(
            id=obs.id,
            observation_type=obs.observation_type.value,
            timestamp=obs.timestamp,
            target_id=obs.target_id,
            scan_job_id=obs.scan_job_id,
            predictions=obs.predictions,
            has_ground_truth=obs.ground_truth is not None
        )
        for obs in observations
    ]


@router.get("/observations/detail/{observation_id}", response_model=ObservationDetail)
async def get_observation_detail(
    observation_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Get detailed information about a specific observation.
    
    Includes raw data, features, predictions, and ground truth.
    """
    result = await db.execute(
        select(ObservationModel).where(ObservationModel.id == observation_id)
    )
    observation = result.scalar_one_or_none()
    
    if not observation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Observation {observation_id} not found"
        )
    
    return ObservationDetail(
        id=observation.id,
        observation_type=observation.observation_type,
        timestamp=observation.timestamp,
        target_id=observation.target_id,
        scan_job_id=observation.scan_job_id,
        raw_data=observation.raw_data,
        features=observation.features,
        predictions=observation.predictions,
        ground_truth=observation.ground_truth,
        ground_truth_source=observation.ground_truth_source
    )


@router.get("/stats")
async def get_feedback_stats(
    db: AsyncSession = Depends(get_db)
):
    """
    Get statistics about feedback and ground truth.
    
    Useful for monitoring learning progress.
    """
    from sqlalchemy import func
    
    # Total observations
    total_obs_result = await db.execute(
        select(func.count(ObservationModel.id))
    )
    total_observations = total_obs_result.scalar() or 0
    
    # Observations with ground truth
    with_gt_result = await db.execute(
        select(func.count(ObservationModel.id))
        .where(ObservationModel.ground_truth.isnot(None))
    )
    observations_with_ground_truth = with_gt_result.scalar() or 0
    
    # Feedback by type
    feedback_by_type = {}
    for ft in FeedbackType:
        count_result = await db.execute(
            select(func.count(FeedbackModel.id))
            .where(FeedbackModel.feedback_type == ft.value)
        )
        feedback_by_type[ft.value] = count_result.scalar() or 0
    
    # Total feedback
    total_feedback_result = await db.execute(
        select(func.count(FeedbackModel.id))
    )
    total_feedback = total_feedback_result.scalar() or 0
    
    # Calculate ground truth ratio
    gt_ratio = (
        observations_with_ground_truth / total_observations 
        if total_observations > 0 else 0
    )
    
    return {
        "total_observations": total_observations,
        "observations_with_ground_truth": observations_with_ground_truth,
        "ground_truth_ratio": round(gt_ratio, 4),
        "total_feedback": total_feedback,
        "feedback_by_type": feedback_by_type,
        "ready_for_training": observations_with_ground_truth >= 100,
        "recommendations": _get_recommendations(
            total_observations,
            observations_with_ground_truth,
            feedback_by_type
        )
    }


def _get_recommendations(total_obs: int, with_gt: int, by_type: dict) -> List[str]:
    """Generate recommendations for improving training data."""
    recommendations = []
    
    if total_obs == 0:
        recommendations.append("Run some scans to generate observations")
    elif with_gt == 0:
        recommendations.append("Start validating observations to create ground truth")
    elif with_gt < 100:
        recommendations.append(f"Need {100 - with_gt} more validated observations before training")
    elif with_gt >= 100 and with_gt < 1000:
        recommendations.append("Good progress! Continue validating to improve model accuracy")
    else:
        recommendations.append("Sufficient training data available. Consider running training pipeline")
    
    # Check for imbalanced feedback
    tp = by_type.get("true_positive", 0)
    fp = by_type.get("false_positive", 0)
    if tp > 0 and fp > 0:
        ratio = tp / (tp + fp)
        if ratio > 0.9:
            recommendations.append("Warning: Training data is heavily biased toward true positives")
        elif ratio < 0.1:
            recommendations.append("Warning: Training data is heavily biased toward false positives")
    
    return recommendations


# ============== Batch Operations ==============

class BulkFeedbackItem(BaseModel):
    observation_id: str
    feedback_type: FeedbackType


class BulkFeedbackCreate(BaseModel):
    items: List[BulkFeedbackItem]
    source: str = "api"


@router.post("/bulk", response_model=dict)
async def create_bulk_feedback(
    bulk: BulkFeedbackCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Submit feedback for multiple observations at once.
    
    Useful for quickly validating batches of findings.
    """
    success_count = 0
    errors = []
    
    for item in bulk.items:
        try:
            # Verify observation exists
            result = await db.execute(
                select(ObservationModel).where(ObservationModel.id == item.observation_id)
            )
            observation = result.scalar_one_or_none()
            
            if not observation:
                errors.append({"observation_id": item.observation_id, "error": "Not found"})
                continue
            
            # Update ground truth
            observation.ground_truth = {
                "feedback_type": item.feedback_type.value,
                "is_true_positive": item.feedback_type == FeedbackType.TRUE_POSITIVE
            }
            observation.ground_truth_source = bulk.source
            observation.ground_truth_timestamp = datetime.utcnow()
            
            # Create feedback record
            db_feedback = FeedbackModel(
                observation_id=item.observation_id,
                feedback_type=item.feedback_type.value,
                feedback_value={},
                source=bulk.source,
                created_at=datetime.utcnow()
            )
            db.add(db_feedback)
            
            success_count += 1
            
        except Exception as e:
            errors.append({"observation_id": item.observation_id, "error": str(e)})
    
    await db.commit()
    
    return {
        "success_count": success_count,
        "error_count": len(errors),
        "errors": errors if errors else None
    }