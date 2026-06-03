package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/httpx"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/panel"
)

type PanelNodes struct {
	Pool *pgxpool.Pool
}

func (h *PanelNodes) Mount(r chi.Router) {
	r.Route("/panel/nodes", func(nr chi.Router) {
		nr.Get("/{id}/openvpn-settings", h.getOpenvpnSettings)
		nr.Post("/{id}/openvpn-settings", h.postOpenvpnSettings)
		nr.Get("/{id}/firewall", h.getFirewall)
		nr.Post("/{id}/firewall-apply", h.applyFirewall)
		nr.Post("/{id}/firewall-check", h.checkFirewall)
		nr.Post("/{id}/root-ca/remove", h.removeRootCa)
		nr.Post("/{id}/openvpn-settings-apply", h.applyOpenvpnSettings)
		nr.Post("/{id}/openvpn-service", h.postOpenvpnService)
		nr.Post("/{id}/openvpn-check-config", h.postOpenvpnCheckConfig)
		nr.Post("/{id}/agent-update", h.postAgentUpdate)
		nr.Get("/{id}/openvpn-logs", h.getOpenvpnLogs)
		nr.Get("/{id}/openvpn-raw-config", h.getOpenvpnRawConfig)
		nr.Get("/{id}/network-info", h.getNetworkInfo)
		nr.Get("/{id}/system-services", h.getSystemServices)
		nr.Post("/{id}/system-service-unit", h.postSystemServiceUnit)
		nr.Post("/{id}/dnsmasq/apply-task", h.enqueueDnsmasqApplyTask)
		nr.Get("/{id}/dnsmasq", h.getDnsmasq)
		nr.Post("/{id}/dnsmasq", h.postDnsmasq)
		nr.Get("/{id}/openvpn-materials", h.listOpenvpnMaterials)
		nr.Post("/{id}/openvpn-materials", h.createOpenvpnMaterial)
		nr.Delete("/{id}/openvpn-materials/{materialId}", h.deleteOpenvpnMaterial)
		nr.Post("/{id}/server-certificate", h.issueServerCertificate)
		nr.Delete("/{id}/server-certificate", h.deleteServerCertificate)
		nr.Post("/{id}/server-certificate-import", h.importServerCertificate)
	})
}

func (h *PanelNodes) writeResult(w http.ResponseWriter, r panel.Result) {
	httpx.WriteJSON(w, r.Status, r.Body)
}

func (h *PanelNodes) getOpenvpnSettings(w http.ResponseWriter, r *http.Request) {
	h.writeResult(w, panel.GetOpenvpnSettingsForPanel(r.Context(), h.Pool, chi.URLParam(r, "id")))
}

func (h *PanelNodes) postOpenvpnSettings(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	h.writeResult(w, panel.PostOpenvpnSettingsForPanel(r.Context(), h.Pool, chi.URLParam(r, "id"), body))
}

func (h *PanelNodes) getFirewall(w http.ResponseWriter, r *http.Request) {
	h.writeResult(w, panel.GetFirewallConfigForPanel(r.Context(), h.Pool, chi.URLParam(r, "id")))
}

func (h *PanelNodes) applyFirewall(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	h.writeResult(w, panel.ApplyFirewallConfigForPanel(r.Context(), h.Pool, chi.URLParam(r, "id"), body))
}

func (h *PanelNodes) checkFirewall(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	h.writeResult(w, panel.CheckFirewallConfigForPanel(r.Context(), h.Pool, chi.URLParam(r, "id"), body))
}

func (h *PanelNodes) removeRootCa(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	h.writeResult(w, panel.RemoveRootCaForPanel(r.Context(), h.Pool, chi.URLParam(r, "id"), body))
}

func (h *PanelNodes) applyOpenvpnSettings(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	h.writeResult(w, panel.ApplyOpenvpnSettingsForPanel(r.Context(), h.Pool, chi.URLParam(r, "id"), body))
}

func (h *PanelNodes) postOpenvpnService(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	h.writeResult(w, panel.PostOpenvpnServiceActionForPanel(r.Context(), h.Pool, chi.URLParam(r, "id"), body))
}

func (h *PanelNodes) postOpenvpnCheckConfig(w http.ResponseWriter, r *http.Request) {
	h.writeResult(w, panel.PostOpenvpnCheckConfigForPanel(r.Context(), h.Pool, chi.URLParam(r, "id")))
}

func (h *PanelNodes) postAgentUpdate(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	h.writeResult(w, panel.PostAgentUpdateForPanel(r.Context(), h.Pool, chi.URLParam(r, "id"), body))
}

func (h *PanelNodes) getOpenvpnLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("pageSize"))
	h.writeResult(w, panel.GetOpenvpnLogsForPanel(r.Context(), h.Pool, chi.URLParam(r, "id"), panel.LogsQuery{
		Page: page, PageSize: pageSize, Q: q.Get("q"),
	}))
}

func (h *PanelNodes) getOpenvpnRawConfig(w http.ResponseWriter, r *http.Request) {
	h.writeResult(w, panel.GetOpenvpnRawConfigForPanel(r.Context(), h.Pool, chi.URLParam(r, "id")))
}

func (h *PanelNodes) getNetworkInfo(w http.ResponseWriter, r *http.Request) {
	h.writeResult(w, panel.GetNodeNetworkInfoForPanel(r.Context(), h.Pool, chi.URLParam(r, "id")))
}

func (h *PanelNodes) getSystemServices(w http.ResponseWriter, r *http.Request) {
	h.writeResult(w, panel.GetNodeSystemServicesForPanel(r.Context(), h.Pool, chi.URLParam(r, "id")))
}

func (h *PanelNodes) postSystemServiceUnit(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	h.writeResult(w, panel.PostNodeSystemServiceUnitActionForPanel(r.Context(), h.Pool, chi.URLParam(r, "id"), body))
}

func (h *PanelNodes) enqueueDnsmasqApplyTask(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	h.writeResult(w, panel.EnqueueDnsmasqApplyTaskForPanel(r.Context(), h.Pool, chi.URLParam(r, "id"), body))
}

func (h *PanelNodes) getDnsmasq(w http.ResponseWriter, r *http.Request) {
	h.writeResult(w, panel.GetDnsmasqForPanel(r.Context(), h.Pool, chi.URLParam(r, "id")))
}

func (h *PanelNodes) postDnsmasq(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	h.writeResult(w, panel.PostDnsmasqForPanel(r.Context(), h.Pool, chi.URLParam(r, "id"), body))
}

func (h *PanelNodes) listOpenvpnMaterials(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	var filter string
	if kind == "dh" || kind == "tls_auth" {
		filter = kind
	}
	rows, err := panel.ListNodeOpenvpnMaterials(r.Context(), h.Pool, id, filter)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rows == nil {
		httpx.WriteError(w, http.StatusNotFound, "Node not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, rows)
}

func (h *PanelNodes) createOpenvpnMaterial(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	kind := strAny(body["kind"])
	label := strAny(body["label"])
	var pemPtr *string
	if pem, ok := body["pem"].(string); ok {
		pemPtr = &pem
	}
	row, err := panel.CreateNodeOpenvpnMaterial(r.Context(), h.Pool, chi.URLParam(r, "id"), kind, label, pemPtr)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, row)
}

func (h *PanelNodes) deleteOpenvpnMaterial(w http.ResponseWriter, r *http.Request) {
	ok, err := panel.DeleteNodeOpenvpnMaterial(r.Context(), h.Pool, chi.URLParam(r, "id"), chi.URLParam(r, "materialId"))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "Материал не найден")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *PanelNodes) issueServerCertificate(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	validityDays, _ := strconv.Atoi(strAny(body["validityDays"]))
	keySize, _ := strconv.Atoi(strAny(body["keySize"]))
	certRow, err := panel.IssueServerCertificateForAgentNode(r.Context(), h.Pool, panel.IssueServerCertInput{
		AgentNodeID: chi.URLParam(r, "id"), RootCaID: strAny(body["rootCaId"]),
		CommonName: strAny(body["commonName"]), ValidityDays: validityDays,
		KeySize: keySize, SignatureAlgorithm: strAny(body["signatureAlgorithm"]),
	})
	if err != nil {
		code := http.StatusBadRequest
		if strings.Contains(err.Error(), "уже есть") {
			code = http.StatusConflict
		}
		httpx.WriteError(w, code, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, certRow)
}

func (h *PanelNodes) deleteServerCertificate(w http.ResponseWriter, r *http.Request) {
	if err := panel.DeleteServerCertificateForAgentNode(r.Context(), h.Pool, chi.URLParam(r, "id")); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *PanelNodes) importServerCertificate(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := httpx.DecodeJSONLoose(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	certRow, err := panel.ImportServerCertificateForAgentNode(r.Context(), h.Pool, panel.ImportServerCertInput{
		AgentNodeID: chi.URLParam(r, "id"), RootCaID: strAny(body["rootCaId"]),
		CertPEM: strAny(body["certPem"]), KeyPEM: strAny(body["keyPem"]),
	})
	if err != nil {
		code := http.StatusBadRequest
		if strings.Contains(err.Error(), "уже есть") {
			code = http.StatusConflict
		}
		httpx.WriteError(w, code, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, certRow)
}
