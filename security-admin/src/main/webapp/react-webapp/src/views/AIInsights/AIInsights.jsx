/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import React, { useCallback, useEffect, useState } from "react";
import { Alert, Badge, Button, Table } from "react-bootstrap";
import { Navigate } from "react-router-dom";
import { Loader } from "Components/CommonComponents";
import { fetchApi } from "Utils/fetchAPI";
import { isSystemAdmin } from "Utils/XAUtils";

/*
  Read-only view of the report produced by the ranger-ai-agent service
  (RANGER-5278). Reviewing, approving, applying and rolling back suggestions
  stay in the agent's command line on purpose. Every value from the report is
  rendered as React text, which escapes it.
*/

const STATUS_VARIANT = {
  PENDING: "warning",
  APPROVED: "info",
  REJECTED: "secondary",
  APPLIED: "success",
  ROLLED_BACK: "dark",
  EXPIRED: "light"
};

const show = (value) =>
  value === null || value === undefined || value === "" ? "-" : String(value);

const confidence = (value) =>
  typeof value === "number" ? value.toFixed(2) : "-";

const asList = (value) => (Array.isArray(value) ? value : []);

const LOAD_FAILED = "Unable to load AI Insights.";

function errorMessage(error) {
  const status = error?.response?.status;

  if (status === 403) {
    return "Only system administrators can view AI Insights.";
  }

  if (status === 502 || status === 503) {
    // The Ranger Admin server sends a short generic message for these.
    return error?.response?.data?.msgDesc || LOAD_FAILED;
  }

  return LOAD_FAILED;
}

function SuggestionDetails({ suggestion }) {
  const evidence = asList(suggestion.evidence);
  const caveats = asList(suggestion.caveats);

  return (
    <details>
      <summary>{show(suggestion.summary)}</summary>
      <p className="mt-2 mb-1">{show(suggestion.rationale)}</p>
      {evidence.length > 0 && (
        <React.Fragment>
          <strong>Evidence</strong>
          <ul className="mb-1">
            {evidence.map((item, index) => (
              <li key={`evidence-${index}`}>{show(item)}</li>
            ))}
          </ul>
        </React.Fragment>
      )}
      {caveats.length > 0 && (
        <React.Fragment>
          <strong>Caveats</strong>
          <ul className="mb-1">
            {caveats.map((item, index) => (
              <li key={`caveat-${index}`}>{show(item)}</li>
            ))}
          </ul>
        </React.Fragment>
      )}
    </details>
  );
}

function ModeBanner({ data }) {
  const mode = data.mode || {};
  const log = data.action_log || {};

  return (
    <div className="mb-3" data-id="ai-insights-mode">
      <Badge bg={mode.dry_run ? "info" : "warning"} className="me-2">
        {mode.dry_run ? "Dry-run: changes are not applied" : "Live apply"}
      </Badge>
      <Badge bg={mode.kill_switch ? "danger" : "secondary"} className="me-2">
        {mode.kill_switch ? "Kill switch ON" : "Kill switch off"}
      </Badge>
      <Badge bg="secondary" className="me-2">
        {`Max ${show(mode.max_changes_per_day)} changes/day`}
      </Badge>
      <Badge bg={log.intact ? "success" : "danger"} className="me-2">
        {log.intact
          ? `Action log intact (${show(log.entries)} entries)`
          : "Action log failed verification"}
      </Badge>
      <span className="text-muted">{`Generated ${show(
        data.generated_at
      )}`}</span>
    </div>
  );
}

function Counts({ counts }) {
  const entries = Object.entries(counts || {});

  if (entries.length === 0) {
    return null;
  }

  return (
    <div className="mb-3" data-id="ai-insights-counts">
      {entries.map(([status, count]) => (
        <Badge
          key={status}
          bg={STATUS_VARIANT[status] || "secondary"}
          className="me-2"
        >
          {`${status}: ${show(count)}`}
        </Badge>
      ))}
    </div>
  );
}

function SuggestionsTable({ suggestions }) {
  return (
    <React.Fragment>
      <h5 className="mt-4">Suggestions</h5>
      <Table striped bordered hover size="sm" data-id="ai-insights-suggestions">
        <thead>
          <tr>
            <th>ID</th>
            <th>Status</th>
            <th>Policy / user</th>
            <th>Proposed change</th>
            <th>Confidence</th>
            <th>Explanation</th>
            <th>Review</th>
          </tr>
        </thead>
        <tbody>
          {suggestions.length === 0 ? (
            <tr>
              <td colSpan={7} className="text-muted">
                No suggestions yet.
              </td>
            </tr>
          ) : (
            suggestions.map((s) => (
              <tr key={show(s.id)}>
                <td>
                  <code>{show(s.id)}</code>
                </td>
                <td>
                  <Badge bg={STATUS_VARIANT[s.status] || "secondary"}>
                    {show(s.status)}
                  </Badge>
                </td>
                <td>
                  {`Policy ${show(s.policy_id)}`}
                  <div className="text-muted">{show(s.user)}</div>
                </td>
                <td>
                  {show(s.change)}
                  <div className="text-muted">{show(s.kind)}</div>
                </td>
                <td>
                  {confidence(s.confidence)}
                  <div className="text-muted">
                    {`detector ${confidence(
                      s.detector_confidence
                    )} · model ${confidence(s.llm_confidence)}`}
                  </div>
                </td>
                <td>
                  <SuggestionDetails suggestion={s} />
                </td>
                <td>
                  {show(s.reviewed_by)}
                  <div className="text-muted">{show(s.reviewed_at)}</div>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </Table>
    </React.Fragment>
  );
}

function ApplicationsTable({ applications }) {
  return (
    <React.Fragment>
      <h5 className="mt-4">Applied changes</h5>
      <Table striped bordered hover size="sm" data-id="ai-insights-applications">
        <thead>
          <tr>
            <th>Suggestion</th>
            <th>Policy</th>
            <th>Applied</th>
            <th>Policy version</th>
            <th>Rolled back</th>
          </tr>
        </thead>
        <tbody>
          {applications.length === 0 ? (
            <tr>
              <td colSpan={5} className="text-muted">
                Nothing has been applied.
              </td>
            </tr>
          ) : (
            applications.map((a) => (
              <tr key={show(a.application_id)}>
                <td>
                  <code>{show(a.suggestion_id)}</code>
                </td>
                <td>{show(a.policy_id)}</td>
                <td>
                  {show(a.applied_at)}
                  <div className="text-muted">{show(a.applied_by)}</div>
                </td>
                <td>{`${show(a.version_before)} → ${show(
                  a.version_after
                )}`}</td>
                <td>
                  {a.rolled_back_at ? (
                    <React.Fragment>
                      {show(a.rolled_back_at)}
                      <div className="text-muted">{show(a.rolled_back_by)}</div>
                    </React.Fragment>
                  ) : (
                    "-"
                  )}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </Table>
    </React.Fragment>
  );
}

function ActivityTable({ entries }) {
  return (
    <React.Fragment>
      <h5 className="mt-4">Recent activity</h5>
      <Table striped bordered hover size="sm" data-id="ai-insights-log">
        <thead>
          <tr>
            <th>Time</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Suggestion</th>
          </tr>
        </thead>
        <tbody>
          {entries.length === 0 ? (
            <tr>
              <td colSpan={4} className="text-muted">
                No activity yet.
              </td>
            </tr>
          ) : (
            entries.map((e, index) => (
              <tr key={`log-${index}`}>
                <td>{show(e.ts)}</td>
                <td>{show(e.actor)}</td>
                <td>{show(e.action)}</td>
                <td>
                  <code>{show(e.suggestion_id)}</code>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </Table>
    </React.Fragment>
  );
}

function AIInsights() {
  const allowed = isSystemAdmin();
  const [state, setState] = useState({ status: "loading" });

  const load = useCallback(async () => {
    setState({ status: "loading" });

    try {
      const resp = await fetchApi({
        url: "ai-insights/report",
        // show the problem on this page instead of redirecting away
        skipNavigate: true
      });
      const data = resp?.data;

      if (!data || typeof data !== "object") {
        setState({ status: "error", message: LOAD_FAILED });
      } else if (data.enabled === false) {
        setState({ status: "disabled" });
      } else {
        setState({ status: "ready", data });
      }
    } catch (error) {
      console.error("Error occurred while fetching AI insights");
      setState({ status: "error", message: errorMessage(error) });
    }
  }, []);

  useEffect(() => {
    if (allowed) {
      load();
    }
  }, [allowed, load]);

  if (!allowed) {
    return <Navigate to="/forbidden" replace />;
  }

  return (
    <React.Fragment>
      <div className="header-wraper">
        <h3 className="wrap-header bold">AI Insights</h3>
        <Button
          variant="outline-secondary"
          size="sm"
          onClick={load}
          disabled={state.status === "loading"}
          data-id="ai-insights-refresh"
        >
          Refresh
        </Button>
      </div>
      <div className="wrap">
        <p className="text-muted">
          Read-only view of suggestions from the Ranger AI agent. To approve,
          apply or roll back a suggestion, use the agent command line.
        </p>
        {state.status === "loading" && <Loader />}
        {state.status === "disabled" && (
          <Alert variant="info" data-id="ai-insights-disabled">
            AI Insights is not enabled. An administrator can turn it on with
            the ranger.ai.insights.* settings in ranger-admin-site.xml.
          </Alert>
        )}
        {state.status === "error" && (
          <Alert variant="danger" data-id="ai-insights-error">
            {state.message}
          </Alert>
        )}
        {state.status === "ready" && (
          <React.Fragment>
            <ModeBanner data={state.data} />
            <Counts counts={state.data.counts} />
            <SuggestionsTable suggestions={asList(state.data.suggestions)} />
            <ApplicationsTable applications={asList(state.data.applications)} />
            <ActivityTable entries={asList(state.data.recent_log)} />
          </React.Fragment>
        )}
      </div>
    </React.Fragment>
  );
}

export default AIInsights;
