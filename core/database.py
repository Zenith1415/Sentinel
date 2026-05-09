"""
MongoDB Atlas async client (motor) for the self-healing pipeline.

Five collections:
  pipelines, findings, patches, rollback_events, rl_rewards

All public methods are async (motor). Use _fire_db() in sync contexts
to write without blocking the pipeline thread.
"""
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_db_instance = None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Database:
    """Async MongoDB Atlas client wrapping the 5 pipeline collections."""

    def __init__(self) -> None:
        uri     = os.getenv("MONGODB_URI", "")
        db_name = os.getenv("MONGODB_DB_NAME", os.getenv("MONGODB_DB", "self_healing_contracts"))
        self._client = None
        self._db     = None
        if not uri:
            logger.warning("MONGODB_URI not set — Database writes will be no-ops")
            return
        try:
            from motor.motor_asyncio import AsyncIOMotorClient
            self._client = AsyncIOMotorClient(uri)
            self._db     = self._client[db_name]
        except ImportError:
            logger.warning("motor not installed — Database writes will be no-ops")
        except Exception as exc:
            logger.warning("Database init error: %s", exc)

    def _col(self, name: str):
        return self._db[name] if self._db is not None else None

    # ------------------------------------------------------------------
    # Pipelines
    # ------------------------------------------------------------------

    async def save_pipeline(self, state: dict) -> str:
        col = self._col("pipelines")
        if col is None:
            return state.get("pipeline_id", "")
        now = _utcnow()
        pipeline_id = state.get("pipeline_id", str(uuid.uuid4()))
        doc = {
            "_id":               pipeline_id,
            "contract_address":  state.get("contract_address", ""),
            "contract_source":   state.get("contract_source", ""),
            "tvl_estimate":      state.get("tvl_estimate", 0.0),
            "route":             state.get("route", "medium"),
            "confidence_score":  state.get("confidence_score", 0.0),
            "all_findings":      state.get("all_findings", []),
            "candidate_patches": state.get("candidate_patches", []),
            "gate_results":      state.get("gate_results", {}),
            "selected_patch":    state.get("selected_patch", ""),
            "deployed":          state.get("deployed", False),
            "tx_hash":           state.get("tx_hash", ""),
            "healed":            state.get("healed", False),
            "rl_reward":         state.get("rl_reward", 0.0),
            "created_at":        now,
            "updated_at":        now,
        }
        try:
            await col.replace_one({"_id": pipeline_id}, doc, upsert=True)
        except Exception as exc:
            logger.debug("save_pipeline error: %s", exc)
        return pipeline_id

    async def update_pipeline(self, pipeline_id: str, updates: dict) -> bool:
        col = self._col("pipelines")
        if col is None:
            return False
        updates = dict(updates)
        updates["updated_at"] = _utcnow()
        try:
            result = await col.update_one(
                {"_id": pipeline_id},
                {"$set": updates},
                upsert=True,
            )
            return result.acknowledged
        except Exception as exc:
            logger.debug("update_pipeline error: %s", exc)
            return False

    async def get_pipeline(self, pipeline_id: str) -> dict:
        col = self._col("pipelines")
        if col is None:
            return {}
        try:
            doc = await col.find_one({"_id": pipeline_id})
            return doc or {}
        except Exception as exc:
            logger.debug("get_pipeline error: %s", exc)
            return {}

    async def get_all_pipelines(self, filters: dict | None = None) -> list:
        col = self._col("pipelines")
        if col is None:
            return []
        filters = filters or {}
        query: dict[str, Any] = {}
        if "healed" in filters:
            query["healed"] = filters["healed"]
        if "route" in filters:
            query["route"] = filters["route"]
        if "contract_address" in filters:
            query["contract_address"] = filters["contract_address"]
        limit = int(filters.get("limit", 20))
        try:
            cursor = col.find(query).sort("created_at", -1).limit(limit)
            return await cursor.to_list(length=limit)
        except Exception as exc:
            logger.debug("get_all_pipelines error: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    async def save_finding(self, finding: dict, pipeline_id: str) -> str:
        col = self._col("findings")
        if col is None:
            return ""
        finding_id = str(uuid.uuid4())
        doc = {
            "_id":                finding_id,
            "pipeline_id":        pipeline_id,
            "vuln_type":          finding.get("type", finding.get("vuln_type", "unknown")),
            "severity":           finding.get("severity", "medium"),
            "affected_function":  finding.get("location", finding.get("affected_function", "")),
            "methodology":        finding.get("methodology", finding.get("source", "")),
            "confidence":         finding.get("confidence", 0.5),
            "fix_recommendation": finding.get("suggested_fix", finding.get("fix_recommendation", "")),
            "created_at":         _utcnow(),
        }
        try:
            await col.insert_one(doc)
        except Exception as exc:
            logger.debug("save_finding error: %s", exc)
        return finding_id

    # ------------------------------------------------------------------
    # Patches
    # ------------------------------------------------------------------

    async def save_patch(self, patch: dict, pipeline_id: str) -> str:
        col = self._col("patches")
        if col is None:
            return ""
        patch_id = str(uuid.uuid4())
        doc = {
            "_id":               patch_id,
            "pipeline_id":       pipeline_id,
            "strategy":          patch.get("strategy", "pure_llm"),
            "source":            patch.get("source", ""),
            "gate_results":      patch.get("gate_results", {}),
            "passed_all_gates":  patch.get("passed_all_gates", False),
            "deployed":          patch.get("deployed", False),
            "bytecode_diff_pct": patch.get("bytecode_diff_pct", 0.0),
            "created_at":        _utcnow(),
        }
        try:
            await col.insert_one(doc)
        except Exception as exc:
            logger.debug("save_patch error: %s", exc)
        return patch_id

    # ------------------------------------------------------------------
    # Rollback events
    # ------------------------------------------------------------------

    async def save_rollback_event(self, event: dict) -> str:
        col = self._col("rollback_events")
        if col is None:
            return ""
        event_id = str(uuid.uuid4())
        doc = {
            "_id":              event_id,
            "pipeline_id":      event.get("pipeline_id", ""),
            "contract_address": event.get("contract_address", ""),
            "rollback_target":  event.get("rollback_target", ""),
            "trigger_reason":   event.get("trigger_reason", ""),
            "anomaly_type":     event.get("anomaly_type", ""),
            "tx_hash":          event.get("tx_hash", ""),
            "created_at":       _utcnow(),
        }
        try:
            await col.insert_one(doc)
        except Exception as exc:
            logger.debug("save_rollback_event error: %s", exc)
        return event_id

    # ------------------------------------------------------------------
    # RL rewards
    # ------------------------------------------------------------------

    async def save_rl_reward(self, reward: dict) -> str:
        col = self._col("rl_rewards")
        if col is None:
            return ""
        reward_id = str(uuid.uuid4())
        doc = {
            "_id":         reward_id,
            "pipeline_id": reward.get("pipeline_id", ""),
            "gate":        reward.get("gate", ""),
            "reward":      reward.get("reward", 0.0),
            "cumulative":  reward.get("cumulative", 0.0),
            "phase":       reward.get("phase", "simulation"),
            "created_at":  _utcnow(),
        }
        try:
            await col.insert_one(doc)
        except Exception as exc:
            logger.debug("save_rl_reward error: %s", exc)
        return reward_id

    # ------------------------------------------------------------------
    # Aggregate queries
    # ------------------------------------------------------------------

    async def get_stats(self) -> dict:
        pipelines_col   = self._col("pipelines")
        rollback_col    = self._col("rollback_events")
        findings_col    = self._col("findings")
        empty: dict[str, Any] = {
            "total_pipelines_run":          0,
            "heal_success_rate":             0.0,
            "avg_confidence_score":          0.0,
            "most_common_vuln_types":        [],
            "avg_gates_failed_before_pass":  0.0,
            "rollback_count":                0,
        }
        if pipelines_col is None:
            return empty
        try:
            total  = await pipelines_col.count_documents({})
            healed = await pipelines_col.count_documents({"healed": True})
            success_rate = round(healed / total, 4) if total > 0 else 0.0

            conf_cursor = pipelines_col.aggregate([
                {"$group": {"_id": None, "avg": {"$avg": "$confidence_score"}}}
            ])
            conf_list = await conf_cursor.to_list(1)
            avg_conf = round(conf_list[0]["avg"], 4) if conf_list else 0.0

            rollback_count = 0
            if rollback_col is not None:
                rollback_count = await rollback_col.count_documents({})

            most_common: list[str] = []
            if findings_col is not None:
                type_cursor = findings_col.aggregate([
                    {"$group": {"_id": "$vuln_type", "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}},
                    {"$limit": 5},
                ])
                type_list = await type_cursor.to_list(5)
                most_common = [r["_id"] for r in type_list if r.get("_id")]

            return {
                "total_pipelines_run":          total,
                "heal_success_rate":             success_rate,
                "avg_confidence_score":          avg_conf,
                "most_common_vuln_types":        most_common,
                "avg_gates_failed_before_pass":  0.0,
                "rollback_count":                rollback_count,
            }
        except Exception as exc:
            logger.debug("get_stats error: %s", exc)
            return empty

    async def get_findings_by_type(self) -> list:
        col = self._col("findings")
        if col is None:
            return []
        try:
            cursor = col.aggregate([
                {"$group": {
                    "_id":      {"vuln_type": "$vuln_type", "severity": "$severity"},
                    "count":    {"$sum": 1},
                }},
                {"$project": {
                    "_id":      0,
                    "vuln_type": "$_id.vuln_type",
                    "severity":  "$_id.severity",
                    "count":    1,
                }},
                {"$sort": {"count": -1}},
            ])
            return await cursor.to_list(100)
        except Exception as exc:
            logger.debug("get_findings_by_type error: %s", exc)
            return []

    async def get_rl_learning_curve(self) -> list:
        col = self._col("rl_rewards")
        if col is None:
            return []
        try:
            cursor = col.find(
                {},
                {"_id": 0, "created_at": 1, "cumulative": 1, "phase": 1},
            ).sort("created_at", 1)
            docs = await cursor.to_list(1000)
            return [
                {
                    "timestamp":         d["created_at"].isoformat(),
                    "cumulative_reward": d.get("cumulative", 0.0),
                    "phase":             d.get("phase", "simulation"),
                }
                for d in docs
            ]
        except Exception as exc:
            logger.debug("get_rl_learning_curve error: %s", exc)
            return []


def get_db() -> Database:
    """Return the module-level Database singleton."""
    global _db_instance
    if _db_instance is None:
        _db_instance = Database()
    return _db_instance
