package handlers

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/config"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/httpx"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/panelbackup"
)

const maxRestoreUpload = 500 * 1024 * 1024

type PanelBackups struct {
	Cfg  config.Config
	Pool *pgxpool.Pool
}

func (h *PanelBackups) Mount(r chi.Router) {
	r.Get("/", h.List)
	r.Put("/settings", h.UpdateSettings)
	r.Post("/run", h.Run)
	r.Get("/archives/{id}/download", h.Download)
	r.Delete("/archives/{id}", h.DeleteArchive)
	r.Post("/restore", h.Restore)
}

func (h *PanelBackups) List(w http.ResponseWriter, r *http.Request) {
	settings, err := panelbackup.EnsureBackupSettingsRow(r.Context(), h.Pool)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "Ошибка загрузки настроек резервного копирования")
		return
	}
	rows, err := h.Pool.Query(r.Context(), `
		SELECT b.id, b."fileName", b."sizeBytes", b.trigger, b."createdAt"
		FROM "PanelAppBackup" b ORDER BY b."createdAt" DESC`)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	var backups []map[string]any
	for rows.Next() {
		var id, fileName, trigger string
		var sizeBytes int
		var createdAt time.Time
		if err := rows.Scan(&id, &fileName, &sizeBytes, &trigger, &createdAt); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		backups = append(backups, map[string]any{
			"id": id, "fileName": fileName, "sizeBytes": sizeBytes, "trigger": trigger, "createdAt": createdAt,
		})
	}
	if backups == nil {
		backups = []map[string]any{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"settings": map[string]any{
			"intervalMinutes": settings.IntervalMinutes,
			"retainCount":     settings.RetainCount,
			"lastScheduledAt": settings.LastScheduledAt,
		},
		"backups": backups,
	})
}

func (h *PanelBackups) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	if _, err := panelbackup.EnsureBackupSettingsRow(r.Context(), h.Pool); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "Не удалось сохранить настройки")
		return
	}
	var body struct {
		IntervalMinutes *float64 `json:"intervalMinutes"`
		RetainCount     *float64 `json:"retainCount"`
	}
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	interval := 0
	retain := 10
	if body.IntervalMinutes != nil {
		interval = clampInt(int(*body.IntervalMinutes), 0, 10080)
	}
	if body.RetainCount != nil {
		retain = clampInt(int(*body.RetainCount), 1, 500)
	}
	var prevInterval int
	_ = h.Pool.QueryRow(r.Context(), `SELECT "intervalMinutes" FROM "PanelAppBackupSettings" WHERE id = 1`).Scan(&prevInterval)
	var lastScheduled *time.Time
	if prevInterval == 0 && interval > 0 {
		now := time.Now()
		lastScheduled = &now
	}
	var updated panelbackup.SettingsRow
	err := h.Pool.QueryRow(r.Context(), `
		UPDATE "PanelAppBackupSettings"
		SET "intervalMinutes" = $1, "retainCount" = $2,
			"lastScheduledAt" = COALESCE($3, "lastScheduledAt"), "updatedAt" = NOW()
		WHERE id = 1
		RETURNING "intervalMinutes", "retainCount", "lastScheduledAt"`,
		interval, retain, lastScheduled).Scan(&updated.IntervalMinutes, &updated.RetainCount, &updated.LastScheduledAt)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "Не удалось сохранить настройки")
		return
	}
	_ = panelbackup.PruneOldBackups(r.Context(), h.Pool, h.Cfg.PanelBackupDir)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"settings": map[string]any{
			"intervalMinutes": updated.IntervalMinutes,
			"retainCount":     updated.RetainCount,
			"lastScheduledAt": updated.LastScheduledAt,
		},
	})
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func (h *PanelBackups) Run(w http.ResponseWriter, r *http.Request) {
	created, err := panelbackup.CreatePanelBackupZip(r.Context(), h.Pool, h.Cfg.PanelBackupDir, "manual")
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "Не удалось создать резервную копию")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"backup": map[string]any{
			"id": created.ID, "fileName": created.FileName, "sizeBytes": created.SizeBytes,
			"trigger": created.Trigger, "createdAt": created.CreatedAt,
		},
	})
}

func (h *PanelBackups) Download(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var fileName string
	err := h.Pool.QueryRow(r.Context(), `SELECT "fileName" FROM "PanelAppBackup" WHERE id = $1`, id).Scan(&fileName)
	if err == pgx.ErrNoRows {
		httpx.WriteError(w, http.StatusNotFound, "Копия не найдена")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	abs := filepath.Join(h.Cfg.PanelBackupDir, id+".zip")
	data, err := os.ReadFile(abs)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "Ошибка чтения архива")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+url.PathEscape(fileName)+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (h *PanelBackups) DeleteArchive(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var exists string
	err := h.Pool.QueryRow(r.Context(), `SELECT id FROM "PanelAppBackup" WHERE id = $1`, id).Scan(&exists)
	if err == pgx.ErrNoRows {
		httpx.WriteError(w, http.StatusNotFound, "Копия не найдена")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = os.Remove(filepath.Join(h.Cfg.PanelBackupDir, id+".zip"))
	if _, err := h.Pool.Exec(r.Context(), `DELETE FROM "PanelAppBackup" WHERE id = $1`, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "Не удалось удалить копию")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *PanelBackups) Restore(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(maxRestoreUpload); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "Файл не передан")
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "Файл не передан")
		return
	}
	defer file.Close()
	buf, err := io.ReadAll(io.LimitReader(file, maxRestoreUpload+1))
	if err != nil || len(buf) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "Файл не передан")
		return
	}
	if len(buf) > maxRestoreUpload {
		httpx.WriteError(w, http.StatusBadRequest, "Файл слишком большой")
		return
	}
	if err := panelbackup.RestorePanelFromZipBuffer(r.Context(), h.Pool, h.Cfg.PanelBackupDir, buf); err != nil {
		msg := err.Error()
		if msg == "" {
			msg = "Восстановление не удалось"
		}
		httpx.WriteError(w, http.StatusInternalServerError, msg)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": "Данные восстановлены из архива. Войдите заново при необходимости.",
	})
}