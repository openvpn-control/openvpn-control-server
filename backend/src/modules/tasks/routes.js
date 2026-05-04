import { Router } from "express";
import { listPanelTasks, retryPanelTask } from "../../services/panelTasks.js";

const router = Router();

router.get("/", async (req, res) => {
  const limit = Number(req.query?.limit);
  const rows = await listPanelTasks(Number.isFinite(limit) ? limit : 200);
  res.json(rows);
});

router.post("/:id/retry", async (req, res) => {
  const result = await retryPanelTask(req.params.id);
  if (!result) return res.status(404).json({ error: "Задача не найдена" });
  if (result.error) return res.status(409).json({ error: result.error });
  return res.json(result.task);
});

export default router;
