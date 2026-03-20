"""
Observation storage and retrieval.
"""
from datetime import datetime
from typing import AsyncIterator, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .observation import Observation, ObservationType
from ..persistence.models import ObservationModel


class ObservationStore:
    """Stores and retrieves observations for learning."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def save(self, observation: Observation) -> None:
        """Persist a single observation."""
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
            ground_truth_timestamp=observation.ground_truth_timestamp,
        )
        self.session.add(model)
        await self.session.flush()  # flush but don't commit — let caller control transaction

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
                ground_truth_timestamp=obs.ground_truth_timestamp,
            )
            for obs in observations
        ]
        self.session.add_all(models)
        await self.session.flush()

    async def get_by_scan_job(self, scan_job_id: int) -> List[Observation]:
        result = await self.session.execute(
            select(ObservationModel)
            .where(ObservationModel.scan_job_id == scan_job_id)
            .order_by(ObservationModel.timestamp)
        )
        return [self._to_domain(m) for m in result.scalars().all()]

    async def iter_with_ground_truth(
        self, observation_type: Optional[ObservationType] = None
    ) -> AsyncIterator[Observation]:
        query = select(ObservationModel).where(ObservationModel.ground_truth.isnot(None))
        if observation_type:
            query = query.where(
                ObservationModel.observation_type == observation_type.value
            )
        result = await self.session.stream(query)
        async for (model,) in result:
            yield self._to_domain(model)

    async def update_ground_truth(
        self, observation_id: str, ground_truth: dict, source: str
    ) -> None:
        result = await self.session.execute(
            select(ObservationModel).where(ObservationModel.id == observation_id)
        )
        model = result.scalar_one_or_none()
        if model:
            model.ground_truth = ground_truth
            model.ground_truth_source = source
            model.ground_truth_timestamp = datetime.utcnow()
            await self.session.flush()

    @staticmethod
    def _to_domain(model: ObservationModel) -> Observation:
        return Observation(
            id=model.id,
            observation_type=ObservationType(model.observation_type),
            timestamp=model.timestamp,
            target_id=model.target_id,
            scan_job_id=model.scan_job_id,
            raw_data=model.raw_data,
            features=model.features or {},
            context_ids=model.context_ids or [],
            predictions=model.predictions or {},
            ground_truth=model.ground_truth,
            ground_truth_source=model.ground_truth_source,
            ground_truth_timestamp=model.ground_truth_timestamp,
        )
