"""
Observation storage and retrieval.
"""
from typing import List, Optional, AsyncIterator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .observation import Observation, ObservationType
from ..persistence.models import ObservationModel
from datetime import datetime


class ObservationStore:
    """
    Stores and retrieves observations for learning.
    """
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def save(self, observation: Observation) -> None:
        """Save an observation to the database."""
        model = ObservationModel(
            id=observation.id,
            observation_type=observation.observation_type.value,
            timestamp=observation.timestamp,
            target_id=observation.target_id,
            scan_job_id=observation.scan_job_id,
            raw_data=observation.raw_data,
            features=observation.features,
            context_ids=observation.context_ids,
            predictions=observation.predictions,
            ground_truth=observation.ground_truth,
            ground_truth_source=observation.ground_truth_source,
            ground_truth_timestamp=observation.ground_truth_timestamp
        )
        
        self.session.add(model)
        await self.session.commit()
    
    async def save_batch(self, observations: List[Observation]) -> None:
        """Save multiple observations efficiently."""
        models = [
            ObservationModel(
                id=obs.id,
                observation_type=obs.observation_type.value,
                timestamp=obs.timestamp,
                target_id=obs.target_id,
                scan_job_id=obs.scan_job_id,
                raw_data=obs.raw_data,
                features=obs.features,
                context_ids=obs.context_ids,
                predictions=obs.predictions,
                ground_truth=obs.ground_truth,
                ground_truth_source=obs.ground_truth_source,
                ground_truth_timestamp=obs.ground_truth_timestamp
            )
            for obs in observations
        ]
        
        self.session.add_all(models)
        await self.session.commit()
    
    async def get_by_scan_job(self, scan_job_id: int) -> List[Observation]:
        """Get all observations for a scan job."""
        result = await self.session.execute(
            select(ObservationModel)
            .where(ObservationModel.scan_job_id == scan_job_id)
            .order_by(ObservationModel.timestamp)
        )
        
        models = result.scalars().all()
        return [self._model_to_observation(m) for m in models]
    
    async def iter_with_ground_truth(
        self, 
        observation_type: Optional[ObservationType] = None
    ) -> AsyncIterator[Observation]:
        """
        Iterate through observations that have ground truth.
        Used for training data export.
        """
        query = select(ObservationModel).where(
            ObservationModel.ground_truth.isnot(None)
        )
        
        if observation_type:
            query = query.where(
                ObservationModel.observation_type == observation_type.value
            )
        
        result = await self.session.stream(query)
        
        async for row in result:
            model = row[0]
            yield self._model_to_observation(model)
    
    async def update_ground_truth(
        self,
        observation_id: str,
        ground_truth: dict,
        source: str
    ) -> None:
        """Update ground truth for an observation."""
        result = await self.session.execute(
            select(ObservationModel).where(ObservationModel.id == observation_id)
        )
        model = result.scalar_one_or_none()
        
        if model:
            model.ground_truth = ground_truth
            model.ground_truth_source = source
            model.ground_truth_timestamp = datetime.utcnow()
            await self.session.commit()
    
    def _model_to_observation(self, model: ObservationModel) -> Observation:
        """Convert database model to Observation object."""
        return Observation(
            id=model.id,
            observation_type=ObservationType(model.observation_type),
            timestamp=model.timestamp,
            target_id=model.target_id,
            scan_job_id=model.scan_job_id,
            raw_data=model.raw_data,
            features=model.features,
            context_ids=model.context_ids or [],
            predictions=model.predictions,
            ground_truth=model.ground_truth,
            ground_truth_source=model.ground_truth_source,
            ground_truth_timestamp=model.ground_truth_timestamp
        )