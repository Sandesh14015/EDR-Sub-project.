    let currentIncidentId = null;
    let currentReportMarkdown = "";

    function showAlert(message, type="info") {
      const box = document.getElementById("alertBox");
      box.className = `alert-box ${type}`;
      box.innerText = message;
      box.style.display = "block";
      setTimeout(() => { box.style.display = "none"; }, 4000);
    }

    async function updateStats() {
      try {
        const res = await fetch("/api/status");
        const data = await res.json();
        document.getElementById("statEvents").innerText = data.total_events;
        document.getElementById("statIncidents").innerText = data.total_incidents;
        document.getElementById("statOpen").innerText = data.open_incidents;
      } catch (err) {
        console.error(err);
      }
    }

    async function loadScenario(name) {
      try {
        showAlert(`Loading scenario: ${name}...`);
        const res = await fetch(`/api/scenarios/${name}/load`, { method: "POST" });
        const data = await res.json();
        showAlert(data.message);
        await updateStats();
        await fetchIncidents();
        await fetchEvents();
        if (data.incidents && data.incidents.length > 0) {
          inspectIncident(data.incidents[0].id);
        }
      } catch (err) {
        showAlert("Failed to load scenario: " + err, "error");
      }
    }

    async function ingestLogs() {
      const rawText = document.getElementById("rawInput").value.trim();
      if (!rawText) {
        showAlert("Please paste some log lines or select a pre-built scenario.");
        return;
      }
      try {
        const res = await fetch("/api/ingest", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ raw_data: rawText })
        });
        const data = await res.json();
        showAlert(data.message);
        document.getElementById("rawInput").value = "";
        await updateStats();
        await fetchEvents();
      } catch (err) {
        showAlert("Failed to ingest logs: " + err, "error");
      }
    }

    async function runCorrelation() {
      try {
        showAlert("Running multi-sensor correlation engine...");
        const res = await fetch("/api/correlate", { method: "POST" });
        const data = await res.json();
        showAlert(data.message);
        await updateStats();
        await fetchIncidents();
        if (data.incidents && data.incidents.length > 0) {
          inspectIncident(data.incidents[0].id);
        }
      } catch (err) {
        showAlert("Correlation error: " + err, "error");
      }
    }

    async function clearAllData() {
      if (!confirm("Are you sure you want to clear all events and incidents?")) return;
      try {
        const res = await fetch("/api/clear", { method: "POST" });
        const data = await res.json();
        showAlert(data.message);
        currentIncidentId = null;
        document.getElementById("incidentWorkspace").style.display = "none";
        document.getElementById("noIncidentNotice").style.display = "block";
        await updateStats();
        await fetchIncidents();
        await fetchEvents();
      } catch (err) {
        showAlert("Clear error: " + err, "error");
      }
    }

    function getSeverityTag(sev) {
      const s = (sev || "").toUpperCase();
      if (s === "CRITICAL") return `<span class="tag tag-critical">Critical</span>`;
      if (s === "HIGH") return `<span class="tag tag-high">High</span>`;
      if (s === "MEDIUM") return `<span class="tag tag-medium">Medium</span>`;
      if (s === "MODERATE") return `<span class="tag tag-moderate">Moderate</span>`;
      return `<span class="tag tag-low">Low</span>`;
    }

    async function fetchIncidents() {
      try {
        const res = await fetch("/api/incidents");
        const incidents = await res.json();
        const container = document.getElementById("incidentsContainer");
        if (!incidents || incidents.length === 0) {
          container.innerHTML = `<p style="font-size: 13px; color: #64748b;">No incidents detected yet.</p>`;
          return;
        }
        let html = `<table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Category</th>
              <th>Risk</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>`;
        for (const inc of incidents) {
          html += `<tr>
            <td><strong>${inc.id}</strong></td>
            <td>${inc.threat_category}</td>
            <td>${getSeverityTag(inc.severity)} <strong>${inc.risk_score}</strong></td>
            <td><span style="font-size: 11px; font-weight: 600;">${inc.status}</span></td>
            <td><button style="padding: 3px 8px; font-size: 11px;" onclick="inspectIncident('${inc.id}')">Inspect</button></td>
          </tr>`;
        }
        html += `</tbody></table>`;
        container.innerHTML = html;
      } catch (err) {
        console.error(err);
      }
    }

    async function inspectIncident(incidentId) {
      currentIncidentId = incidentId;
      try {
        const res = await fetch(`/api/incidents/${incidentId}`);
        const data = await res.json();
        const inc = data.incident;

        document.getElementById("noIncidentNotice").style.display = "none";
        document.getElementById("incidentWorkspace").style.display = "block";
        document.getElementById("detailHeading").innerText = `Incident ${inc.id}: ${inc.threat_category}`;
        document.getElementById("detailBadge").innerHTML = getSeverityTag(inc.severity);

        document.getElementById("incTitle").innerText = inc.title;
        document.getElementById("incDesc").innerText = inc.description;
        document.getElementById("statusSelect").value = inc.status;
        document.getElementById("incRisk").innerText = inc.risk_score;
        document.getElementById("incConfidence").innerText = inc.confidence;
        document.getElementById("incAffected").innerText = inc.affected_assets.join(", ") || "N/A";
        document.getElementById("incDest").innerText = inc.destination_entities.join(", ") || "N/A";

        // Render Timeline
        const tContainer = document.getElementById("timelineContainer");
        if (data.timeline && data.timeline.length > 0) {
          let tHtml = "";
          for (const item of data.timeline) {
            const isInferred = item.is_inferred;
            tHtml += `
              <div class="timeline-item ${isInferred ? 'inferred' : ''}">
                <div class="timeline-time">${item.timestamp} | ${item.source} ${isInferred ? '<span class="inferred-pill">Inferred Hypothesis</span>' : ''}</div>
                <div class="timeline-stage">${item.stage}</div>
                <div class="timeline-desc">${item.description}</div>
              </div>`;
          }
          tContainer.innerHTML = tHtml;
        } else {
          tContainer.innerHTML = `<p style="font-size: 13px; color: #64748b;">No timeline entries.</p>`;
        }

        // Render Evidence
        const eContainer = document.getElementById("evidenceContainer");
        if (data.evidence && data.evidence.length > 0) {
          let eHtml = `<table><thead><tr><th>Source</th><th>Type</th><th>Observed Evidence</th><th>Context</th></tr></thead><tbody>`;
          for (const ev of data.evidence) {
            const srcTag = ev.source === "suricata" ? `<span class="tag tag-source-suricata">Suricata</span>` : `<span class="tag tag-source-zeek">Zeek</span>`;
            eHtml += `<tr>
              <td>${srcTag}</td>
              <td><strong>${ev.type}</strong></td>
              <td><code>${ev.value}</code></td>
              <td>${ev.description}</td>
            </tr>`;
          }
          eHtml += `</tbody></table>`;
          eContainer.innerHTML = eHtml;
        } else {
          eContainer.innerHTML = `<p style="font-size: 13px; color: #64748b;">No corroborated evidence stored.</p>`;
        }

        // Render Recommendations
        const rContainer = document.getElementById("recommendationsContainer");
        if (data.recommendations && data.recommendations.length > 0) {
          let rHtml = `<ul style="list-style-type: none; padding: 0;">`;
          for (const rec of data.recommendations) {
            const badgeClass = rec.priority === "HIGH" ? "tag-critical" : (rec.priority === "MEDIUM" ? "tag-medium" : "tag-low");
            rHtml += `
              <li style="margin-bottom: 10px; padding: 10px; border: 1px solid #e2e8f0; border-radius: 6px;">
                <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 4px;">
                  <span class="tag ${badgeClass}">${rec.priority}</span>
                  <span style="font-size: 12px; font-weight: 700; color: #475569;">${rec.category} Action</span>
                </div>
                <div style="font-size: 13px; color: #1e293b;">${rec.recommendation}</div>
              </li>`;
          }
          rHtml += `</ul>`;
          rContainer.innerHTML = rHtml;
        } else {
          rContainer.innerHTML = `<p style="font-size: 13px; color: #64748b;">No recommendations available.</p>`;
        }

        // Fetch Report
        const repRes = await fetch(`/api/incidents/${incidentId}/report`);
        const repData = await repRes.json();
        currentReportMarkdown = repData.markdown;
        document.getElementById("reportPre").innerText = repData.markdown;

        // Reset to first tab
        switchTab("timeline");

      } catch (err) {
        console.error(err);
      }
    }

    function switchTab(tabName) {
      const tabs = ["timeline", "evidence", "recommendations", "report"];
      for (const t of tabs) {
        const btn = document.getElementById(`tabBtn${t.charAt(0).toUpperCase() + t.slice(1)}`);
        const content = document.getElementById(`tabContent${t.charAt(0).toUpperCase() + t.slice(1)}`);
        if (t === tabName) {
          btn.classList.add("active");
          content.style.display = "block";
        } else {
          btn.classList.remove("active");
          content.style.display = "none";
        }
      }
    }

    async function updateIncidentStatus() {
      if (!currentIncidentId) return;
      const newStatus = document.getElementById("statusSelect").value;
      try {
        const res = await fetch(`/api/incidents/${currentIncidentId}/status`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ status: newStatus })
        });
        const data = await res.json();
        showAlert(data.message);
        await updateStats();
        await fetchIncidents();
      } catch (err) {
        showAlert("Failed to update status: " + err, "error");
      }
    }

    function copyReport() {
      if (!currentReportMarkdown) return;
      navigator.clipboard.writeText(currentReportMarkdown);
      showAlert("Incident report copied to clipboard!");
    }

    function downloadReport() {
      if (!currentReportMarkdown) return;
      const blob = new Blob([currentReportMarkdown], { type: "text/markdown" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `report_${currentIncidentId || 'incident'}.md`;
      a.click();
      URL.revokeObjectURL(url);
    }

    async function fetchEvents() {
      try {
        const res = await fetch("/api/events?limit=50");
        const events = await res.json();
        const container = document.getElementById("eventsContainer");
        if (!events || events.length === 0) {
          container.innerHTML = `<p style="font-size: 13px; color: #64748b;">No normalized events stored.</p>`;
          return;
        }
        let html = `<table>
          <thead>
            <tr>
              <th>Source</th>
              <th>Type</th>
              <th>Connection</th>
              <th>Signature / Summary</th>
            </tr>
          </thead>
          <tbody>`;
        for (const ev of events) {
          const srcTag = ev.source === "suricata" ? `<span class="tag tag-source-suricata">Suricata</span>` : `<span class="tag tag-source-zeek">Zeek</span>`;
          html += `<tr>
            <td>${srcTag}</td>
            <td>${ev.event_type}</td>
            <td><code style="font-size: 11px;">${ev.src_ip || '*'}:${ev.src_port || '*'} -> ${ev.dst_ip || '*'}:${ev.dst_port || '*'}</code></td>
            <td style="font-size: 12px;">${ev.signature || '-'}</td>
          </tr>`;
        }
        html += `</tbody></table>`;
        container.innerHTML = html;
      } catch (err) {
        console.error(err);
      }
    }

    // Auto-init on page load
    window.addEventListener("DOMContentLoaded", () => {
      updateStats();
      fetchIncidents();
      fetchEvents();
    });
