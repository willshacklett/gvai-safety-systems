"use strict";

(() => {
  const recorded = JSON.parse(document.getElementById("recorded-results").textContent);
  const actions = new Map(recorded.actions.map((action) => [action.action, action]));
  const scenarios = {
    safe_work: {
      title: "Permitted operation",
      kind: "Prototype allowed",
      description: "The recorded prototype permitted this safe-work action and committed its output.",
      action: "safe_work",
    },
    protected_file_attack: {
      title: "Protected-file attempt",
      kind: "Prototype denied",
      description: "A protected-file write attempt was observed. The prototype denied the transaction; the report records no OS boundary failure.",
      action: "protected_file_attack",
    },
    network_attack: {
      title: "Network attempt",
      kind: "Prototype denied",
      description: "An unapproved network-egress attempt was observed. The prototype denied the transaction; the report records no OS boundary failure.",
      action: "network_attack",
    },
    process_attack: {
      title: "Process-spawn attempt",
      kind: "Prototype denied",
      description: "An unauthorized process-spawn attempt was observed. The prototype denied the transaction; the report records no OS boundary failure.",
      action: "process_attack",
    },
    commit_outcome: {
      title: "Authoritative result",
      kind: "Recorded commit outcome",
      description: "The experiment reported one authoritative output file. The safe-work scenario committed; the three individual attack scenarios did not.",
      action: null,
    },
  };

  const elements = {
    title: document.getElementById("result-title"),
    kind: document.getElementById("result-kind"),
    description: document.getElementById("result-description"),
    decision: document.getElementById("result-decision"),
    effect: document.getElementById("result-effect"),
    commit: document.getElementById("result-commit"),
    status: document.getElementById("walkthrough-status"),
  };

  function showScenario(key) {
    const scenario = scenarios[key];
    if (!scenario) return;

    const result = scenario.action ? actions.get(scenario.action) : null;
    if (scenario.action && !result) return;

    elements.title.textContent = scenario.title;
    elements.kind.textContent = scenario.kind;
    elements.description.textContent = scenario.description;

    if (result) {
      elements.decision.textContent = result.allowed ? "ALLOWED by prototype" : "DENIED by prototype";
      elements.effect.textContent = result.observed_effects.join(", ");
      elements.commit.textContent = result.committed ? "Committed" : "Not committed";
    } else {
      elements.decision.textContent = "Recorded experiment passed";
      elements.effect.textContent = "Selected filesystem, network, and process-creation scenarios";
      elements.commit.textContent = recorded.authoritative_files.join(", ");
    }

    elements.status.textContent = `Showing ${scenario.title.toLowerCase()}.`;
  }

  document.querySelectorAll("[data-scenario]").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll("[data-scenario]").forEach((candidate) => {
        candidate.setAttribute("aria-pressed", String(candidate === button));
      });
      showScenario(button.dataset.scenario);
    });
  });

  showScenario("safe_work");
})();
